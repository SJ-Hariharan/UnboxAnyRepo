/**
 * Read-only view over a sanitized snapshot for analysers. Text is decoded
 * lazily as UTF-8; invalid UTF-8 is treated as "not text".
 */
import type { SourceFile } from '../source/archive.ts';
import { isPlainObject } from '../detect/util.ts';

const utf8 = new TextDecoder('utf-8', { fatal: true });

export class SourceView {
  readonly files: readonly SourceFile[];
  readonly dirs: readonly string[];
  readonly present: ReadonlySet<string>;
  readonly totalBytes: number;
  private readonly texts: ReadonlyMap<string, Buffer>;
  private readonly cache = new Map<string, string | null>();

  constructor(input: { files: readonly SourceFile[]; dirs: readonly string[]; texts: ReadonlyMap<string, Buffer>; totalBytes: number }) {
    this.files = input.files;
    this.dirs = input.dirs;
    this.texts = input.texts;
    this.totalBytes = input.totalBytes;
    this.present = new Set(input.files.map((f) => f.path));
  }

  has(path: string): boolean {
    return this.present.has(path);
  }

  /** Paths whose text was kept for analysis. */
  textPaths(): string[] {
    return [...this.texts.keys()];
  }

  /** Decoded text, or undefined if absent, skipped (binary/too large/budget) or not UTF-8. */
  text(path: string): string | undefined {
    if (this.cache.has(path)) return this.cache.get(path) ?? undefined;
    const buf = this.texts.get(path);
    let out: string | null = null;
    if (buf) {
      try {
        out = utf8.decode(buf);
        if (out.charCodeAt(0) === 0xfeff) out = out.slice(1);
      } catch {
        out = null;
      }
    }
    this.cache.set(path, out);
    return out ?? undefined;
  }

  /** Parse JSON text into a plain object, or undefined. */
  json(path: string): Record<string, unknown> | undefined {
    const t = this.text(path);
    if (t === undefined) return undefined;
    try {
      const v: unknown = JSON.parse(t);
      return isPlainObject(v) ? v : undefined;
    } catch {
      return undefined;
    }
  }

  find(re: RegExp): string[] {
    return this.files.filter((f) => re.test(f.path)).map((f) => f.path);
  }
}

/** 1-based line number of a character offset. */
export function lineAt(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/** Split text into lines once, for line-oriented rules. */
export function lines(text: string): string[] {
  return text.split(/\r?\n/);
}
