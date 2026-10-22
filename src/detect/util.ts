import { collapseControlChars } from '../text.ts';
import type { SourceFile } from '../source/archive.ts';

export interface DetectInput {
  files: readonly SourceFile[];
  manifests: ReadonlyMap<string, Buffer>;
}

const utf8 = new TextDecoder('utf-8', { fatal: true });

export type ManifestRead =
  | { state: 'absent' }
  | { state: 'too_large' }
  | { state: 'invalid_encoding' }
  | { state: 'ok'; text: string };

/** Read a manifest the archive layer kept (only small, allowlisted files are kept). */
export function readManifest(input: DetectInput, path: string, present: ReadonlySet<string>): ManifestRead {
  if (!present.has(path)) return { state: 'absent' };
  const buf = input.manifests.get(path);
  if (buf === undefined) return { state: 'too_large' };
  try {
    let text = utf8.decode(buf);
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    return { state: 'ok', text };
  } catch {
    return { state: 'invalid_encoding' };
  }
}

/** Clean untrusted text for display: single line, no control characters, bounded. */
export function displayText(value: string, max = 200): string {
  const t = collapseControlChars(value).trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Own-property string lookup that ignores prototype tricks like "__proto__". */
export function ownString(obj: Record<string, unknown>, key: string): string | undefined {
  if (!Object.hasOwn(obj, key)) return undefined;
  const v = obj[key];
  return typeof v === 'string' ? v : undefined;
}

export function ownObject(obj: Record<string, unknown>, key: string): Record<string, unknown> | undefined {
  if (!Object.hasOwn(obj, key)) return undefined;
  const v = obj[key];
  return isPlainObject(v) ? v : undefined;
}

export function countKeys(obj: Record<string, unknown> | undefined): number {
  return obj ? Object.keys(obj).length : 0;
}
