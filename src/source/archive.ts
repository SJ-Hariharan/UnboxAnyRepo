/**
 * Turn an untrusted GitHub tar.gz into a sanitized snapshot:
 *
 * - every path is validated (no absolute paths, no "..", no control chars,
 *   bounded length/depth, no duplicates or file/dir conflicts);
 * - only regular files and directories are kept; symlinks that stay inside the
 *   tree are skipped (reported), symlinks that escape the tree, hard links,
 *   devices and FIFOs cause the whole archive to be rejected;
 * - modes are normalized (0644 / 0755), ownership is reset;
 * - decompressed size, file count and per-file size are capped while streaming
 *   (gzip-bomb safe);
 * - nested archives are never opened.
 *
 * Nothing is written to the host filesystem. The output is a fresh tar.gz
 * (rooted at `src/`) that only the sandbox ever unpacks.
 */
import path from 'node:path';
import zlib from 'node:zlib';
import { Readable } from 'node:stream';
import { readTar, encodeEntry, endOfArchive, TarError } from './tar.ts';
import type { WriteEntry } from './tar.ts';
import { hasControlChars } from '../text.ts';

export interface ArchiveLimits {
  maxCompressedBytes: number;
  maxUncompressedBytes: number;
  maxFiles: number;
  maxFileBytes: number;
}

export interface SourceFile {
  path: string;
  size: number;
}

export interface SourceSnapshot {
  files: SourceFile[];
  dirs: string[];
  totalBytes: number;
  skippedSymlinks: string[];
  skippedSymlinkCount: number;
  /** Contents of small allowlisted manifest files, keyed by path. */
  manifests: Map<string, Buffer>;
  /** Sanitized tar.gz rooted at src/, plus empty .deps/ and .home/ directories. */
  sanitizedTarGz: Buffer;
  /** pax global "comment" (git archive writes the commit SHA there), if present. */
  archiveCommitComment: string | undefined;
  /** Text files kept for static analysis (only when `collectText` is set). */
  texts: Map<string, Buffer>;
  textStats: TextStats;
}

export interface TextStats {
  collected: number;
  collectedBytes: number;
  skipped: Record<'vendored' | 'binary' | 'generated' | 'too_large' | 'budget', number>;
}

export interface CollectTextOptions {
  maxTotalBytes: number;
  /** Docs, data and fixtures share this smaller budget so they cannot crowd out source code. */
  maxSecondaryBytes: number;
  isSecondary(path: string): boolean;
  /** Returns a skip reason, or null to keep the file (subject to the total budget). */
  skipReason(path: string, size: number): 'vendored' | 'binary' | 'generated' | 'too_large' | null;
  isBinary(data: Buffer): boolean;
}

export class ArchiveError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/** Sandbox user that owns the unpacked workspace. Must match the runner. */
export const SANDBOX_UID = 65532;

const MAX_PATH_BYTES = 1024;
const MAX_DEPTH = 64;
const MAX_SEGMENT_BYTES = 255;
export const MANIFEST_MAX_BYTES = 256 * 1024;

/** Root-level files whose contents detection may read (bounded). */
export function isManifestPath(p: string): boolean {
  if (/^requirements\/[A-Za-z0-9._-]+\.txt$/.test(p)) return true;
  if (p.includes('/')) return false;
  return (
    p === 'package.json' ||
    p === 'pyproject.toml' ||
    p === 'setup.cfg' ||
    p === 'pytest.ini' ||
    p === 'tox.ini' ||
    p === 'go.mod' ||
    p === 'Cargo.toml' ||
    p === 'rust-toolchain' ||
    p === 'rust-toolchain.toml' ||
    /^[A-Za-z0-9._-]*requirements[A-Za-z0-9._-]*\.txt$/.test(p)
  );
}

/**
 * Validate a path relative to the archive root. Returns the normalized path
 * (no trailing slash) or throws.
 */
export function validateRelativePath(rel: string): string {
  if (rel.length === 0) throw new ArchiveError('unsafe_path', 'Empty path in archive');
  if (Buffer.byteLength(rel) > MAX_PATH_BYTES) throw new ArchiveError('unsafe_path', 'Path too long in archive');
  if (hasControlChars(rel)) throw new ArchiveError('unsafe_path', 'Control character in archive path');
  if (rel.startsWith('/')) throw new ArchiveError('unsafe_path', 'Absolute path in archive');
  const trimmed = rel.endsWith('/') ? rel.slice(0, -1) : rel;
  const segments = trimmed.split('/');
  if (segments.length > MAX_DEPTH) throw new ArchiveError('unsafe_path', 'Archive nesting is too deep');
  for (const seg of segments) {
    if (seg === '' || seg === '.' || seg === '..') throw new ArchiveError('unsafe_path', 'Path traversal or empty segment in archive');
    if (seg.split('\\').includes('..')) throw new ArchiveError('unsafe_path', 'Path traversal in archive');
    if (Buffer.byteLength(seg) > MAX_SEGMENT_BYTES) throw new ArchiveError('unsafe_path', 'File name too long in archive');
  }
  return trimmed;
}

/** True when a symlink at `linkPath` pointing to `target` stays within the root. */
export function symlinkStaysInside(linkPath: string, target: string): boolean {
  if (target === '' || target.startsWith('/') || target.includes('\0')) return false;
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(linkPath), target));
  return !(resolved === '..' || resolved.startsWith('../') || resolved.startsWith('/'));
}

export async function sanitizeArchive(
  gz: Buffer,
  limits: ArchiveLimits,
  opts: { expectedSha?: string; collectText?: CollectTextOptions } = {},
): Promise<SourceSnapshot> {
  if (gz.length > limits.maxCompressedBytes) throw new ArchiveError('too_large', 'Repository archive is too large');

  // Cap decompressed bytes (data + tar headers) while streaming.
  const decompressedCap = limits.maxUncompressedBytes + limits.maxFiles * 2048 + 4 * 1024 * 1024;
  const gunzip = zlib.createGunzip();
  let decompressed = 0;
  const source = Readable.from([gz]).pipe(gunzip);
  async function* counted(): AsyncGenerator<Buffer> {
    for await (const chunk of source) {
      decompressed += (chunk as Buffer).length;
      if (decompressed > decompressedCap) {
        source.destroy();
        throw new ArchiveError('too_large', 'Repository archive expands beyond the allowed size');
      }
      yield chunk as Buffer;
    }
  }

  const out = zlib.createGzip({ level: 6 });
  const outChunks: Buffer[] = [];
  out.on('data', (c: Buffer) => outChunks.push(c));
  const outDone = new Promise<void>((resolve, reject) => {
    out.on('end', resolve);
    out.on('error', reject);
  });
  const write = async (parts: Buffer[]) => {
    for (const p of parts) {
      if (!out.write(p)) await new Promise<void>((r) => out.once('drain', r));
    }
  };
  const base = (p: string, mtime: number): WriteEntry => ({ path: p, kind: 'dir', mode: 0o755, mtime, uid: SANDBOX_UID, gid: SANDBOX_UID });

  let root: string | null = null;
  const seen = new Map<string, 'file' | 'dir'>();
  const files: SourceFile[] = [];
  const dirs: string[] = [];
  const manifests = new Map<string, Buffer>();
  const skippedSymlinks: string[] = [];
  let skippedSymlinkCount = 0;
  let totalBytes = 0;
  let entries = 0;
  const texts = new Map<string, Buffer>();
  const textStats: TextStats = { collected: 0, collectedBytes: 0, skipped: { vendored: 0, binary: 0, generated: 0, too_large: 0, budget: 0 } };
  const collect = opts.collectText;
  let secondaryBytes = 0;

  const ensureParents = async (rel: string, mtime: number) => {
    const segs = rel.split('/');
    for (let i = 1; i < segs.length; i++) {
      const parent = segs.slice(0, i).join('/');
      const existing = seen.get(parent);
      if (existing === 'file') throw new ArchiveError('unsafe_path', 'Archive path conflicts with a file');
      if (existing === undefined) {
        seen.set(parent, 'dir');
        dirs.push(parent);
        await write(encodeEntry(base(`src/${parent}`, mtime)));
      }
    }
  };

  let result;
  try {
    await write(encodeEntry(base('.deps', 0)));
    await write(encodeEntry(base('.home', 0)));
    await write(encodeEntry(base('.home/tmp', 0)));
    await write(encodeEntry(base('src', 0)));

    result = await readTar(counted(), { maxFileBytes: limits.maxFileBytes, maxMetaBytes: 256 * 1024 }, async ({ entry, data }) => {
      entries++;
      if (entries > limits.maxFiles) throw new ArchiveError('too_many_files', 'Repository has too many files');

      // Establish and strip the single top-level directory GitHub adds.
      const raw = entry.path.replace(/^\.\//, '');
      if (root === null) {
        const first = raw.replace(/\/$/, '');
        if (entry.kind !== 'dir' || first === '' || first.includes('/')) {
          throw new ArchiveError('unexpected_layout', 'Archive does not have the expected top-level directory');
        }
        validateRelativePath(first);
        root = first;
        return;
      }
      if (raw === `${root}/` || raw === root) return;
      if (!raw.startsWith(`${root}/`)) throw new ArchiveError('unexpected_layout', 'Archive entry outside the top-level directory');
      const rel = validateRelativePath(raw.slice(root.length + 1));

      if (seen.has(rel)) {
        if (entry.kind === 'dir' && seen.get(rel) === 'dir') return; // explicit dir after implicit parent
        throw new ArchiveError('duplicate_entry', 'Archive contains duplicate paths');
      }

      switch (entry.kind) {
        case 'dir': {
          await ensureParents(rel, entry.mtime);
          seen.set(rel, 'dir');
          dirs.push(rel);
          await write(encodeEntry(base(`src/${rel}`, entry.mtime)));
          return;
        }
        case 'file': {
          await ensureParents(rel, entry.mtime);
          const body = data ?? Buffer.alloc(0);
          totalBytes += body.length;
          if (totalBytes > limits.maxUncompressedBytes) {
            throw new ArchiveError('too_large', 'Repository is larger than the allowed unpacked size');
          }
          seen.set(rel, 'file');
          files.push({ path: rel, size: body.length });
          if (isManifestPath(rel) && body.length <= MANIFEST_MAX_BYTES) manifests.set(rel, body);
          if (collect) {
            const reason = collect.skipReason(rel, body.length) ?? (collect.isBinary(body) ? 'binary' : null);
            const secondary = !reason && collect.isSecondary(rel);
            if (reason) textStats.skipped[reason]++;
            else if (textStats.collectedBytes + body.length > collect.maxTotalBytes) textStats.skipped.budget++;
            else if (secondary && secondaryBytes + body.length > collect.maxSecondaryBytes) textStats.skipped.budget++;
            else {
              texts.set(rel, body);
              textStats.collected++;
              textStats.collectedBytes += body.length;
              if (secondary) secondaryBytes += body.length;
            }
          }
          const mode = (entry.mode & 0o111) !== 0 ? 0o755 : 0o644;
          await write(encodeEntry({ path: `src/${rel}`, kind: 'file', mode, mtime: entry.mtime, uid: SANDBOX_UID, gid: SANDBOX_UID, data: body }));
          return;
        }
        case 'symlink': {
          if (!symlinkStaysInside(rel, entry.linkpath)) {
            throw new ArchiveError('unsafe_symlink', 'Archive contains a symlink that points outside the repository');
          }
          await ensureParents(rel, entry.mtime);
          seen.set(rel, 'file'); // occupies the name; nothing may be placed beneath it
          skippedSymlinkCount++;
          if (skippedSymlinks.length < 20) skippedSymlinks.push(rel);
          return;
        }
        case 'hardlink':
          throw new ArchiveError('unsafe_entry', 'Archive contains a hard link, which is not supported');
        default:
          throw new ArchiveError('unsafe_entry', 'Archive contains a device, FIFO or unknown entry type');
      }
    });
    await write([endOfArchive()]);
    out.end();
    await outDone;
  } catch (err) {
    out.destroy();
    source.destroy();
    if (err instanceof ArchiveError) throw err;
    if (err instanceof TarError) {
      if (err.code === 'file_too_large') throw new ArchiveError('file_too_large', err.message);
      throw new ArchiveError('corrupt', 'The repository archive could not be read safely');
    }
    const code = (err as { code?: string } | null)?.code ?? '';
    if (code.startsWith('Z_')) throw new ArchiveError('corrupt', 'The repository archive is not valid gzip data');
    throw err;
  }

  if (root === null) throw new ArchiveError('unexpected_layout', 'Repository archive is empty');
  const comment = result.globalPax.get('comment');
  if (opts.expectedSha && comment !== undefined && comment !== opts.expectedSha) {
    throw new ArchiveError('commit_mismatch', 'Archive commit does not match the requested commit');
  }

  return {
    files,
    dirs,
    totalBytes,
    skippedSymlinks,
    skippedSymlinkCount,
    manifests,
    sanitizedTarGz: Buffer.concat(outChunks),
    archiveCommitComment: comment,
    texts,
    textStats,
  };
}
