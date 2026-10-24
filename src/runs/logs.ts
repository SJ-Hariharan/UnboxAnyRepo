/**
 * Bounded, sanitized run log.
 *
 * Output is split into lines, terminal escape sequences and control characters
 * are removed, credentials are redacted, and only the first `headBytes` plus
 * the last `tailBytes` are retained. Truncation is always made explicit.
 * The UI renders lines with textContent; nothing here is ever HTML.
 */
import { StringDecoder } from 'node:string_decoder';
import { Redactor } from './redact.ts';

export type LineKind = 'out' | 'system';

export interface LogLine {
  seq: number;
  kind: LineKind;
  text: string;
}

const MAX_LINE_CHARS = 4000;

/** Remove ANSI/VT escape sequences and every control character except tab. */
export function sanitizeLine(input: string): string {
  let s = input
    // OSC ... BEL or ST
    .replace(/\u001b\][\s\S]*?(?:\u0007|\u001b\\)/g, '')
    // CSI sequences
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    // Other two-byte escapes
    .replace(/\u001b[@-Z\\-_]/g, '');
  // Carriage returns: keep what a terminal would finally show (text after the last \r).
  const cr = s.lastIndexOf('\r');
  if (cr !== -1) s = s.slice(cr + 1);
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x09) out += '    ';
    else if (c <= 0x1f || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029 || c === 0xfeff) continue;
    else out += s[i];
  }
  return out.length > MAX_LINE_CHARS ? `${out.slice(0, MAX_LINE_CHARS)} … [line truncated]` : out;
}

export interface LogEvents {
  onLine?(line: LogLine): void;
  onTruncated?(): void;
}

export class RunLog {
  private readonly headBytes: number;
  private readonly tailBytes: number;
  private readonly redactor: Redactor;
  private readonly decoders = new Map<string, StringDecoder>();
  private readonly partial = new Map<string, string>();
  private readonly head: LogLine[] = [];
  private headSize = 0;
  private tail: LogLine[] = [];
  private tailSize = 0;
  private seq = 0;
  private truncated = false;
  private droppedLines = 0;
  private droppedBytes = 0;
  /** Total raw bytes received from the sandbox (for an honest activity indicator). */
  receivedBytes = 0;
  events: LogEvents = {};

  constructor(opts: { headBytes: number; tailBytes: number; secretValues?: readonly string[] }) {
    this.headBytes = opts.headBytes;
    this.tailBytes = opts.tailBytes;
    this.redactor = new Redactor(opts.secretValues ?? []);
  }

  get isTruncated(): boolean {
    return this.truncated;
  }

  /** A message from UnboxAnyRepo itself (step banners, outcomes). */
  system(text: string): void {
    this.push('system', sanitizeLine(text));
  }

  /** Raw bytes from a sandboxed process stream. */
  write(stream: string, chunk: Buffer | string): void {
    const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
    this.receivedBytes += buf.length;
    let dec = this.decoders.get(stream);
    if (!dec) {
      dec = new StringDecoder('utf8');
      this.decoders.set(stream, dec);
    }
    const text = (this.partial.get(stream) ?? '') + dec.write(buf);
    const parts = text.split('\n');
    let rest = parts.pop() ?? '';
    for (const p of parts) this.push('out', this.redactor.line(sanitizeLine(p)));
    // Force out very long unterminated lines so memory stays bounded.
    while (rest.length > MAX_LINE_CHARS * 2) {
      this.push('out', this.redactor.line(sanitizeLine(rest.slice(0, MAX_LINE_CHARS))));
      rest = rest.slice(MAX_LINE_CHARS);
    }
    this.partial.set(stream, rest);
  }

  /** Flush any unterminated line for a stream (call when the process exits). */
  end(stream: string): void {
    const dec = this.decoders.get(stream);
    const rest = (this.partial.get(stream) ?? '') + (dec ? dec.end() : '');
    this.partial.delete(stream);
    this.decoders.delete(stream);
    if (rest !== '') this.push('out', this.redactor.line(sanitizeLine(rest)));
  }

  private push(kind: LineKind, text: string): void {
    const line: LogLine = { seq: ++this.seq, kind, text };
    const size = Buffer.byteLength(text) + 1;
    if (!this.truncated && this.headSize + size <= this.headBytes) {
      this.head.push(line);
      this.headSize += size;
      this.events.onLine?.(line);
      return;
    }
    if (!this.truncated) {
      this.truncated = true;
      this.events.onTruncated?.();
    }
    this.tail.push(line);
    this.tailSize += size;
    while (this.tailSize > this.tailBytes && this.tail.length > 1) {
      const dropped = this.tail.shift() as LogLine;
      const ds = Buffer.byteLength(dropped.text) + 1;
      this.tailSize -= ds;
      this.droppedLines++;
      this.droppedBytes += ds;
    }
  }

  /** Lines retained in the head section with seq > after (for live streaming). */
  headSince(after: number): LogLine[] {
    return this.head.filter((l) => l.seq > after);
  }

  /** Final retained lines, with an explicit truncation marker between head and tail. */
  retained(): LogLine[] {
    if (!this.truncated) return [...this.head];
    const marker: LogLine = {
      seq: 0,
      kind: 'system',
      text: `[${this.droppedLines} line(s), ${formatBytes(this.droppedBytes)} of output omitted; only the first ${formatBytes(this.headBytes)} and last ${formatBytes(this.tailBytes)} are kept]`,
    };
    return [...this.head, marker, ...this.tail];
  }

  /** Plain-text rendering of the retained log. */
  toText(): string {
    return this.retained()
      .map((l) => (l.kind === 'system' ? `# ${l.text}` : l.text))
      .join('\n');
  }

  stats() {
    return { truncated: this.truncated, receivedBytes: this.receivedBytes, droppedLines: this.droppedLines };
  }
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
