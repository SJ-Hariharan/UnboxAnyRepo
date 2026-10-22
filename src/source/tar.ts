/**
 * Small, strict streaming tar reader and writer.
 *
 * The reader understands ustar, GNU long names (L/K) and pax extended headers
 * (x/g), verifies header checksums, enforces size limits before buffering any
 * data, and rejects invalid UTF-8 names. It never touches the filesystem.
 *
 * The writer emits ustar entries (with a pax header for long or non-ASCII
 * names) for regular files and directories only.
 */

export type EntryKind = 'file' | 'dir' | 'symlink' | 'hardlink' | 'other';

export interface TarEntry {
  path: string;
  kind: EntryKind;
  typeflag: string;
  size: number;
  mode: number;
  linkpath: string;
  mtime: number;
}

export interface TarReadLimits {
  maxFileBytes: number;
  maxMetaBytes: number;
}

export class TarError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

const BLOCK = 512;
const utf8 = new TextDecoder('utf-8', { fatal: true });

class ByteReader {
  private buffers: Buffer[] = [];
  private length = 0;
  private done = false;
  private readonly it: AsyncIterator<Buffer>;

  constructor(source: AsyncIterable<Buffer>) {
    this.it = source[Symbol.asyncIterator]();
  }

  private async fill(n: number): Promise<boolean> {
    while (this.length < n && !this.done) {
      const r = await this.it.next();
      if (r.done) {
        this.done = true;
        break;
      }
      const chunk = Buffer.isBuffer(r.value) ? r.value : Buffer.from(r.value);
      if (chunk.length === 0) continue;
      this.buffers.push(chunk);
      this.length += chunk.length;
    }
    return this.length >= n;
  }

  /** Read exactly n bytes, or return null at a clean EOF with nothing buffered. */
  async read(n: number): Promise<Buffer | null> {
    if (n === 0) return Buffer.alloc(0);
    const ok = await this.fill(n);
    if (!ok) {
      if (this.length === 0) return null;
      throw new TarError('truncated', 'Archive ended unexpectedly');
    }
    const all = this.buffers.length === 1 ? (this.buffers[0] as Buffer) : Buffer.concat(this.buffers, this.length);
    const out = all.subarray(0, n);
    const rest = all.subarray(n);
    this.buffers = rest.length > 0 ? [rest] : [];
    this.length = rest.length;
    return out;
  }

  async skip(n: number): Promise<void> {
    let remaining = n;
    while (remaining > 0) {
      const step = Math.min(remaining, 1024 * 1024);
      const b = await this.read(step);
      if (b === null) throw new TarError('truncated', 'Archive ended unexpectedly');
      remaining -= step;
    }
  }
}

function cstr(buf: Buffer, start: number, len: number): Buffer {
  const slice = buf.subarray(start, start + len);
  const nul = slice.indexOf(0);
  return nul === -1 ? slice : slice.subarray(0, nul);
}

function decodeName(bytes: Buffer): string {
  try {
    return utf8.decode(bytes);
  } catch {
    throw new TarError('bad_name', 'Archive contains a file name that is not valid UTF-8');
  }
}

function parseNumeric(buf: Buffer, start: number, len: number): number {
  const field = buf.subarray(start, start + len);
  if (((field[0] as number) & 0x80) !== 0) {
    // GNU base-256. We only accept positive values that fit in a safe integer.
    if (((field[0] as number) & 0x40) !== 0) throw new TarError('bad_header', 'Negative numeric field');
    let value = (field[0] as number) & 0x3f;
    for (let i = 1; i < field.length; i++) {
      value = value * 256 + (field[i] as number);
      if (value > Number.MAX_SAFE_INTEGER) throw new TarError('bad_header', 'Numeric field too large');
    }
    return value;
  }
  const text = cstr(buf, start, len).toString('latin1').trim();
  if (text === '') return 0;
  if (!/^[0-7]+$/.test(text)) throw new TarError('bad_header', 'Invalid numeric field in tar header');
  const value = parseInt(text, 8);
  if (!Number.isSafeInteger(value)) throw new TarError('bad_header', 'Numeric field too large');
  return value;
}

function verifyChecksum(header: Buffer): void {
  const stored = parseNumeric(header, 148, 8);
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 32 : (header[i] as number);
  if (sum !== stored) throw new TarError('bad_checksum', 'Tar header checksum mismatch');
}

function parsePax(data: Buffer): Map<string, string> {
  const out = new Map<string, string>();
  let pos = 0;
  while (pos < data.length) {
    const space = data.indexOf(0x20, pos);
    if (space === -1) throw new TarError('bad_pax', 'Malformed pax header');
    const lenText = data.subarray(pos, space).toString('latin1');
    if (!/^\d{1,7}$/.test(lenText)) throw new TarError('bad_pax', 'Malformed pax header');
    const recLen = Number(lenText);
    if (recLen <= space - pos + 1 || pos + recLen > data.length) throw new TarError('bad_pax', 'Malformed pax header');
    const record = data.subarray(space + 1, pos + recLen);
    if (record[record.length - 1] !== 0x0a) throw new TarError('bad_pax', 'Malformed pax header');
    const eq = record.indexOf(0x3d);
    if (eq <= 0) throw new TarError('bad_pax', 'Malformed pax header');
    const key = record.subarray(0, eq).toString('latin1');
    const value = decodeName(record.subarray(eq + 1, record.length - 1));
    out.set(key, value);
    pos += recLen;
  }
  return out;
}

function kindOf(typeflag: string): EntryKind {
  switch (typeflag) {
    case '0':
    case '\0':
    case '7':
      return 'file';
    case '5':
      return 'dir';
    case '2':
      return 'symlink';
    case '1':
      return 'hardlink';
    default:
      return 'other';
  }
}

export interface TarItem {
  entry: TarEntry;
  /** File contents for regular files; undefined otherwise. */
  data?: Buffer;
}

export interface TarStreamResult {
  globalPax: Map<string, string>;
}

/**
 * Parse a tar stream. `onItem` is awaited for each entry. Throws TarError on
 * any malformed or over-limit input.
 */
export async function readTar(
  source: AsyncIterable<Buffer>,
  limits: TarReadLimits,
  onItem: (item: TarItem) => Promise<void> | void,
): Promise<TarStreamResult> {
  const reader = new ByteReader(source);
  const globalPax = new Map<string, string>();
  let pendingPax: Map<string, string> | null = null;
  let pendingLongName: string | null = null;
  let pendingLongLink: string | null = null;

  for (;;) {
    const header = await reader.read(BLOCK);
    if (header === null) break; // EOF without end marker: tolerated
    if (header.every((b) => b === 0)) break; // end-of-archive marker
    verifyChecksum(header);

    const typeflag = String.fromCharCode(header[156] as number);
    const size = parseNumeric(header, 124, 12);
    const padded = Math.ceil(size / BLOCK) * BLOCK;
    const magic = header.subarray(257, 263).toString('latin1');

    if (typeflag === 'x' || typeflag === 'g' || typeflag === 'L' || typeflag === 'K') {
      if (size > limits.maxMetaBytes) throw new TarError('too_large', 'Archive metadata header too large');
      const data = await reader.read(size);
      if (data === null) throw new TarError('truncated', 'Archive ended unexpectedly');
      await reader.skip(padded - size);
      if (typeflag === 'x') pendingPax = parsePax(data);
      else if (typeflag === 'g') for (const [k, v] of parsePax(data)) globalPax.set(k, v);
      else if (typeflag === 'L') pendingLongName = decodeName(cstr(data, 0, data.length));
      else pendingLongLink = decodeName(cstr(data, 0, data.length));
      continue;
    }

    let path = decodeName(cstr(header, 0, 100));
    if (magic === 'ustar\0') {
      const prefix = decodeName(cstr(header, 345, 155));
      if (prefix !== '') path = `${prefix}/${path}`;
    }
    let linkpath = decodeName(cstr(header, 157, 100));
    let effectiveSize = size;
    if (pendingLongName !== null) path = pendingLongName;
    if (pendingLongLink !== null) linkpath = pendingLongLink;
    if (pendingPax) {
      const p = pendingPax.get('path');
      if (p !== undefined) path = p;
      const l = pendingPax.get('linkpath');
      if (l !== undefined) linkpath = l;
      const s = pendingPax.get('size');
      if (s !== undefined) {
        if (!/^\d{1,15}$/.test(s)) throw new TarError('bad_pax', 'Invalid pax size');
        effectiveSize = Number(s);
      }
    }
    pendingPax = null;
    pendingLongName = null;
    pendingLongLink = null;

    const entry: TarEntry = {
      path,
      kind: kindOf(typeflag),
      typeflag,
      size: effectiveSize,
      mode: parseNumeric(header, 100, 8),
      linkpath,
      mtime: parseNumeric(header, 136, 12),
    };
    const dataPadded = Math.ceil(effectiveSize / BLOCK) * BLOCK;

    if (entry.kind === 'file') {
      if (effectiveSize > limits.maxFileBytes) {
        throw new TarError('file_too_large', 'A file in the archive exceeds the per-file size limit');
      }
      const data = await reader.read(effectiveSize);
      if (data === null) throw new TarError('truncated', 'Archive ended unexpectedly');
      await reader.skip(dataPadded - effectiveSize);
      await onItem({ entry, data: Buffer.from(data) });
    } else {
      // Non-file entries should carry no data; skip whatever is declared (bounded).
      if (effectiveSize > limits.maxMetaBytes) throw new TarError('too_large', 'Unexpected data on a non-file entry');
      await reader.skip(dataPadded);
      await onItem({ entry });
    }
  }
  return { globalPax };
}

// ---------------------------------------------------------------- writer

export interface WriteEntry {
  path: string;
  kind: 'file' | 'dir';
  mode: number;
  mtime: number;
  uid: number;
  gid: number;
  data?: Buffer;
}

function octal(value: number, width: number): string {
  return value.toString(8).padStart(width - 1, '0') + '\0';
}

function rawHeader(name: Buffer, size: number, mode: number, mtime: number, uid: number, gid: number, typeflag: string): Buffer {
  const h = Buffer.alloc(BLOCK, 0);
  name.copy(h, 0, 0, Math.min(name.length, 100));
  h.write(octal(mode & 0o7777, 8), 100, 'latin1');
  h.write(octal(uid, 8), 108, 'latin1');
  h.write(octal(gid, 8), 116, 'latin1');
  h.write(octal(size, 12), 124, 'latin1');
  h.write(octal(Math.max(0, Math.floor(mtime)), 12), 136, 'latin1');
  h.fill(0x20, 148, 156);
  h.write(typeflag, 156, 'latin1');
  h.write('ustar\0', 257, 'latin1');
  h.write('00', 263, 'latin1');
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += h[i] as number;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'latin1');
  return h;
}

function pad(size: number): Buffer {
  const rem = size % BLOCK;
  return rem === 0 ? Buffer.alloc(0) : Buffer.alloc(BLOCK - rem, 0);
}

function paxRecord(key: string, value: string): Buffer {
  const body = ` ${key}=${value}\n`;
  let len = Buffer.byteLength(body) + 1;
  while (String(len).length + Buffer.byteLength(body) !== len) len = String(len).length + Buffer.byteLength(body);
  return Buffer.from(`${len}${body}`, 'utf8');
}

/** Serialize one entry (header [+ pax header] + data + padding). */
export function encodeEntry(e: WriteEntry): Buffer[] {
  const name = e.kind === 'dir' && !e.path.endsWith('/') ? `${e.path}/` : e.path;
  const nameBytes = Buffer.from(name, 'utf8');
  const parts: Buffer[] = [];
  const asciiShort = nameBytes.length <= 99 && /^[\x20-\x7e]*$/.test(name);
  if (!asciiShort) {
    const pax = paxRecord('path', name);
    parts.push(rawHeader(Buffer.from('PaxHeader', 'latin1'), pax.length, 0o644, e.mtime, e.uid, e.gid, 'x'), pax, pad(pax.length));
  }
  const shortName = asciiShort ? nameBytes : Buffer.from(name.replace(/[^\x20-\x7e]/g, '_').slice(-99), 'latin1');
  const size = e.kind === 'file' ? (e.data?.length ?? 0) : 0;
  parts.push(rawHeader(shortName, size, e.mode, e.mtime, e.uid, e.gid, e.kind === 'dir' ? '5' : '0'));
  if (e.kind === 'file' && e.data && e.data.length > 0) parts.push(e.data, pad(e.data.length));
  return parts;
}

export function endOfArchive(): Buffer {
  return Buffer.alloc(BLOCK * 2, 0);
}
