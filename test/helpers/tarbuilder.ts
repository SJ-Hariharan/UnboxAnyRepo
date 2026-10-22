/** Test-only tar builder that can produce deliberately malicious archives. */
import zlib from 'node:zlib';

export interface RawEntry {
  name: string;
  type?: string; // typeflag
  data?: Buffer | string;
  linkname?: string;
  mode?: number;
  /** Override the size field (to lie about sizes). */
  sizeOverride?: number;
  /** Emit a pax header with these records before the entry. */
  pax?: Record<string, string>;
  /** Emit a GNU long-name (L) entry before this entry. */
  gnuLongName?: string;
  /** Corrupt the checksum. */
  badChecksum?: boolean;
}

function octal(n: number, width: number): string {
  return n.toString(8).padStart(width - 1, '0') + '\0';
}

function header(name: string, size: number, type: string, linkname = '', mode = 0o644, badChecksum = false): Buffer {
  const h = Buffer.alloc(512, 0);
  Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write(octal(mode, 8), 100, 'latin1');
  h.write(octal(0, 8), 108, 'latin1');
  h.write(octal(0, 8), 116, 'latin1');
  h.write(octal(size, 12), 124, 'latin1');
  h.write(octal(1700000000, 12), 136, 'latin1');
  h.fill(0x20, 148, 156);
  h.write(type, 156, 'latin1');
  Buffer.from(linkname, 'utf8').copy(h, 157, 0, 100);
  h.write('ustar\0', 257, 'latin1');
  h.write('00', 263, 'latin1');
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += h[i] as number;
  if (badChecksum) sum += 1;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'latin1');
  return h;
}

function pad(n: number): Buffer {
  return Buffer.alloc((512 - (n % 512)) % 512, 0);
}

function paxBody(records: Record<string, string>): Buffer {
  const parts: Buffer[] = [];
  for (const [k, v] of Object.entries(records)) {
    const body = ` ${k}=${v}\n`;
    let len = Buffer.byteLength(body) + 1;
    while (String(len).length + Buffer.byteLength(body) !== len) len = String(len).length + Buffer.byteLength(body);
    parts.push(Buffer.from(`${len}${body}`, 'utf8'));
  }
  return Buffer.concat(parts);
}

export function buildTar(entries: RawEntry[], opts: { globalComment?: string; noEnd?: boolean } = {}): Buffer {
  const parts: Buffer[] = [];
  if (opts.globalComment !== undefined) {
    const body = paxBody({ comment: opts.globalComment });
    parts.push(header('pax_global_header', body.length, 'g'), body, pad(body.length));
  }
  for (const e of entries) {
    const data = typeof e.data === 'string' ? Buffer.from(e.data, 'utf8') : (e.data ?? Buffer.alloc(0));
    if (e.pax) {
      const body = paxBody(e.pax);
      parts.push(header('PaxHeader', body.length, 'x'), body, pad(body.length));
    }
    if (e.gnuLongName !== undefined) {
      const body = Buffer.from(`${e.gnuLongName}\0`, 'utf8');
      parts.push(header('././@LongLink', body.length, 'L'), body, pad(body.length));
    }
    const type = e.type ?? '0';
    const size = e.sizeOverride ?? (type === '0' ? data.length : 0);
    parts.push(header(e.name, size, type, e.linkname ?? '', e.mode ?? (type === '5' ? 0o755 : 0o644), e.badChecksum));
    if (type === '0' && data.length > 0) parts.push(data, pad(data.length));
  }
  if (!opts.noEnd) parts.push(Buffer.alloc(1024, 0));
  return Buffer.concat(parts);
}

export function gz(buf: Buffer): Buffer {
  return zlib.gzipSync(buf);
}

/** Convenience: a GitHub-style archive with top dir "owner-repo-abc1234/". */
export function repoArchive(files: Record<string, string>, extra: RawEntry[] = [], globalComment?: string): Buffer {
  const root = 'owner-repo-abc1234';
  const entries: RawEntry[] = [{ name: `${root}/`, type: '5' }];
  for (const [p, content] of Object.entries(files)) entries.push({ name: `${root}/${p}`, data: content });
  entries.push(...extra.map((e) => ({ ...e, name: e.name.startsWith('/') || e.name.startsWith('..') ? e.name : `${root}/${e.name}` })));
  return gz(buildTar(entries, globalComment !== undefined ? { globalComment } : {}));
}

export const ROOT = 'owner-repo-abc1234';
