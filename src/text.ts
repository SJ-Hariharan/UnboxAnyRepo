/**
 * Character-class helpers implemented with numeric code points (no regex
 * escapes), shared by every place that validates or cleans untrusted text.
 */

/** C0/C1 control characters, DEL, and the Unicode line/paragraph separators. */
export function isControlCode(code: number): boolean {
  return code <= 0x1f || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029;
}

/** True if the string contains any control character (and optionally a space). */
export function hasControlChars(s: string, opts: { rejectSpace?: boolean } = {}): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (isControlCode(c) || (opts.rejectSpace === true && c === 0x20)) return true;
  }
  return false;
}

/** Replace runs of control characters with a single space (optionally keeping \n and \t). */
export function collapseControlChars(s: string, opts: { keepNewlines?: boolean } = {}): string {
  let out = '';
  let inRun = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (opts.keepNewlines === true && (c === 0x0a || c === 0x09)) {
      out += s[i];
      inRun = false;
    } else if (isControlCode(c)) {
      if (!inRun) out += ' ';
      inRun = true;
    } else {
      out += s[i];
      inRun = false;
    }
  }
  return out;
}
