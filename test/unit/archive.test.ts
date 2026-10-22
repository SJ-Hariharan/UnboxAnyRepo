import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, readFileSync, lstatSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { sanitizeArchive, ArchiveError, validateRelativePath, symlinkStaysInside } from '../../src/source/archive.ts';
import type { ArchiveLimits } from '../../src/source/archive.ts';
import { buildTar, gz, repoArchive, ROOT } from '../helpers/tarbuilder.ts';

const LIMITS: ArchiveLimits = {
  maxCompressedBytes: 5 * 1024 * 1024,
  maxUncompressedBytes: 10 * 1024 * 1024,
  maxFiles: 1000,
  maxFileBytes: 2 * 1024 * 1024,
};

async function rejectsWith(buf: Buffer, code: string, limits: ArchiveLimits = LIMITS) {
  await assert.rejects(sanitizeArchive(buf, limits), (e: unknown) => {
    assert.ok(e instanceof ArchiveError, `expected ArchiveError, got ${String(e)}`);
    assert.equal(e.code, code);
    return true;
  });
}

test('sanitizes a normal archive and keeps manifests', async () => {
  const snap = await sanitizeArchive(
    repoArchive({ 'package.json': '{"name":"x"}', 'src/index.js': 'console.log(1)', 'README.md': '# hi' }),
    LIMITS,
  );
  assert.deepEqual(snap.files.map((f) => f.path).sort(), ['README.md', 'package.json', 'src/index.js']);
  assert.ok(snap.dirs.includes('src'));
  assert.equal(snap.manifests.get('package.json')?.toString(), '{"name":"x"}');
  assert.equal(snap.manifests.has('README.md'), false);
  assert.equal(snap.totalBytes, 12 + 14 + 4);
});

test('sanitized output unpacks with GNU tar to exactly the expected tree, modes normalized', async () => {
  const archive = gz(
    buildTar([
      { name: `${ROOT}/`, type: '5' },
      { name: `${ROOT}/run.sh`, data: '#!/bin/sh\n', mode: 0o4755 },
      { name: `${ROOT}/docs/`, type: '5', mode: 0o777 },
      { name: `${ROOT}/docs/a.md`, data: 'a', mode: 0o666 },
      { name: `${ROOT}/x`, type: '0', data: 'long', pax: { path: `${ROOT}/${'deep/'.repeat(30)}file-ünïcode.txt` } },
    ]),
  );
  const snap = await sanitizeArchive(archive, LIMITS);
  const dir = mkdtempSync(path.join(tmpdir(), 'rr-tar-'));
  try {
    const tarPath = path.join(dir, 'out.tar');
    writeFileSync(tarPath, zlib.gunzipSync(snap.sanitizedTarGz));
    const extractDir = path.join(dir, 'x');
    execFileSync('mkdir', [extractDir]);
    execFileSync('tar', ['-x', '--no-same-owner', '-f', tarPath, '-C', extractDir]);
    const listing = execFileSync('tar', ['-t', '-f', tarPath]).toString().trim().split('\n').sort();
    assert.ok(listing.includes('src/run.sh'));
    assert.ok(listing.includes('.deps/') && listing.includes('.home/tmp/'));
    assert.equal(readFileSync(path.join(extractDir, 'src/run.sh'), 'utf8'), '#!/bin/sh\n');
    assert.equal(lstatSync(path.join(extractDir, 'src/run.sh')).mode & 0o7777, 0o755);
    assert.equal(lstatSync(path.join(extractDir, 'src/docs/a.md')).mode & 0o7777, 0o644);
    const deep = path.join(extractDir, 'src', ...Array(30).fill('deep'), 'file-ünïcode.txt');
    assert.equal(readFileSync(deep, 'utf8'), 'long');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rejects path traversal, absolute paths and odd segments', async () => {
  await rejectsWith(gz(buildTar([{ name: `${ROOT}/`, type: '5' }, { name: `${ROOT}/../../etc/passwd`, data: 'x' }])), 'unsafe_path');
  await rejectsWith(gz(buildTar([{ name: `${ROOT}/`, type: '5' }, { name: '/etc/passwd', data: 'x' }])), 'unexpected_layout');
  await rejectsWith(gz(buildTar([{ name: `${ROOT}/`, type: '5' }, { name: `${ROOT}/a//b`, data: 'x' }])), 'unsafe_path');
  await rejectsWith(gz(buildTar([{ name: `${ROOT}/`, type: '5' }, { name: `${ROOT}/a/./b`, data: 'x' }])), 'unsafe_path');
  await rejectsWith(gz(buildTar([{ name: `${ROOT}/`, type: '5' }, { name: `${ROOT}/a\\..\\..\\b`, data: 'x' }])), 'unsafe_path');
  await rejectsWith(gz(buildTar([{ name: `${ROOT}/`, type: '5' }, { name: `${ROOT}/bad\u0007name`, data: 'x' }])), 'unsafe_path');
  // Traversal smuggled through a pax path or a GNU long name
  await rejectsWith(
    gz(buildTar([{ name: `${ROOT}/`, type: '5' }, { name: `${ROOT}/ok`, data: 'x', pax: { path: `${ROOT}/../../../tmp/pwn` } }])),
    'unsafe_path',
  );
  await rejectsWith(
    gz(buildTar([{ name: `${ROOT}/`, type: '5' }, { name: `${ROOT}/ok`, data: 'x', gnuLongName: `${ROOT}/../escape` }])),
    'unsafe_path',
  );
  // Archive without a single top directory
  await rejectsWith(gz(buildTar([{ name: 'file.txt', data: 'x' }])), 'unexpected_layout');
});

test('symlinks: escaping links reject the archive, internal links are skipped and reported', async () => {
  await rejectsWith(repoArchive({ a: 'x' }, [{ name: 'evil', type: '2', linkname: '/etc/passwd' }]), 'unsafe_symlink');
  await rejectsWith(repoArchive({ a: 'x' }, [{ name: 'evil', type: '2', linkname: '../../../../etc' }]), 'unsafe_symlink');
  await rejectsWith(repoArchive({ a: 'x' }, [{ name: 'sub/evil', type: '2', linkname: '../..' }]), 'unsafe_symlink');
  const ok = await sanitizeArchive(repoArchive({ 'docs/readme.md': 'x' }, [{ name: 'README.md', type: '2', linkname: 'docs/readme.md' }]), LIMITS);
  assert.equal(ok.skippedSymlinkCount, 1);
  assert.deepEqual(ok.skippedSymlinks, ['README.md']);
  assert.equal(ok.files.some((f) => f.path === 'README.md'), false);
  // Nothing may be written beneath a symlinked name.
  await rejectsWith(repoArchive({}, [{ name: 'lnk', type: '2', linkname: 'docs' }, { name: 'lnk/x', data: 'y' }]), 'unsafe_path');
});

test('rejects hard links, devices and FIFOs', async () => {
  await rejectsWith(repoArchive({ a: 'x' }, [{ name: 'h', type: '1', linkname: `${ROOT}/a` }]), 'unsafe_entry');
  await rejectsWith(repoArchive({}, [{ name: 'dev', type: '3' }]), 'unsafe_entry');
  await rejectsWith(repoArchive({}, [{ name: 'blk', type: '4' }]), 'unsafe_entry');
  await rejectsWith(repoArchive({}, [{ name: 'fifo', type: '6' }]), 'unsafe_entry');
});

test('rejects duplicates and file/directory conflicts', async () => {
  await rejectsWith(gz(buildTar([{ name: `${ROOT}/`, type: '5' }, { name: `${ROOT}/a`, data: '1' }, { name: `${ROOT}/a`, data: '2' }])), 'duplicate_entry');
  await rejectsWith(gz(buildTar([{ name: `${ROOT}/`, type: '5' }, { name: `${ROOT}/a`, data: '1' }, { name: `${ROOT}/a/b`, data: '2' }])), 'unsafe_path');
});

test('enforces file count, per-file size, total size and compressed size limits', async () => {
  const many: Record<string, string> = {};
  for (let i = 0; i < 20; i++) many[`f${i}`] = 'x';
  await rejectsWith(repoArchive(many), 'too_many_files', { ...LIMITS, maxFiles: 10 });
  await rejectsWith(repoArchive({ big: 'x'.repeat(5000) }), 'file_too_large', { ...LIMITS, maxFileBytes: 4096 });
  await rejectsWith(repoArchive({ a: 'x'.repeat(3000), b: 'y'.repeat(3000) }), 'too_large', { ...LIMITS, maxUncompressedBytes: 5000 });
  await rejectsWith(repoArchive({ a: 'x' }), 'too_large', { ...LIMITS, maxCompressedBytes: 10 });
});

test('gzip bomb is stopped while streaming', async () => {
  // ~200 MB of zeros declared as one file compresses to ~200 KB.
  const zeros = Buffer.alloc(200 * 1024 * 1024);
  const bomb = gz(buildTar([{ name: `${ROOT}/`, type: '5' }, { name: `${ROOT}/zeros`, data: zeros }]));
  assert.ok(bomb.length < 1024 * 1024);
  const start = Date.now();
  await assert.rejects(sanitizeArchive(bomb, { ...LIMITS, maxFileBytes: 500 * 1024 * 1024 }), ArchiveError);
  assert.ok(Date.now() - start < 10_000);
});

test('rejects corrupt archives: bad checksum, truncated data, lying sizes, non-gzip', async () => {
  await rejectsWith(gz(buildTar([{ name: `${ROOT}/`, type: '5' }, { name: `${ROOT}/a`, data: 'x', badChecksum: true }])), 'corrupt');
  const full = buildTar([{ name: `${ROOT}/`, type: '5' }, { name: `${ROOT}/a`, data: 'x'.repeat(2000) }], { noEnd: true });
  await rejectsWith(gz(full.subarray(0, 1500)), 'corrupt');
  await rejectsWith(gz(buildTar([{ name: `${ROOT}/`, type: '5' }, { name: `${ROOT}/a`, data: 'x', sizeOverride: 999999 }])), 'corrupt');
  await rejectsWith(Buffer.from('this is not gzip'), 'corrupt');
});

test('rejects invalid UTF-8 names', async () => {
  // Second header's name starts with 0xff (invalid UTF-8); the checksum is recomputed so only the name is wrong.
  const bad = Buffer.concat([
    buildTar([{ name: `${ROOT}/`, type: '5' }], { noEnd: true }),
    (() => {
      const h = buildTar([{ name: 'x', data: 'y' }], { noEnd: true });
      h[0] = 0xff;
      // recompute checksum
      h.fill(0x20, 148, 156);
      let sum = 0;
      for (let i = 0; i < 512; i++) sum += h[i] as number;
      h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'latin1');
      return h;
    })(),
    Buffer.alloc(1024),
  ]);
  await rejectsWith(gz(bad), 'corrupt');
});

test('verifies the pax global commit comment when present', async () => {
  const sha = 'a'.repeat(40);
  const good = await sanitizeArchive(repoArchive({ a: 'x' }, [], sha), LIMITS, { expectedSha: sha });
  assert.equal(good.archiveCommitComment, sha);
  await assert.rejects(sanitizeArchive(repoArchive({ a: 'x' }, [], 'b'.repeat(40)), LIMITS, { expectedSha: sha }), (e: unknown) => {
    return e instanceof ArchiveError && e.code === 'commit_mismatch';
  });
});

test('path and symlink helpers', () => {
  assert.equal(validateRelativePath('a/b/'), 'a/b');
  assert.throws(() => validateRelativePath('a/../b'));
  assert.throws(() => validateRelativePath('x'.repeat(300)));
  assert.throws(() => validateRelativePath(Array(70).fill('d').join('/')));
  assert.equal(symlinkStaysInside('a/b', '../c'), true);
  assert.equal(symlinkStaysInside('a/b', '../../c'), false);
  assert.equal(symlinkStaysInside('a', '/abs'), false);
  assert.equal(symlinkStaysInside('a', ''), false);
});
