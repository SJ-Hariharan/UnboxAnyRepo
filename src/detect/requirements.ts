/**
 * Strict reader for pip requirement specifiers.
 *
 * Only plain "name[extras] <version constraints> ; <markers>" lines are
 * accepted. Anything that could change where pip downloads from or make it
 * execute code before tests (index options, -e, URLs, VCS refs, local paths,
 * arbitrary flags) causes rejection with a reason. Accepted specifiers are
 * passed to pip as separate argv elements — never through a shell.
 */

const NAME = '[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?';
const EXTRAS = '(?:\\[\\s*[A-Za-z0-9._-]+(?:\\s*,\\s*[A-Za-z0-9._-]+)*\\s*\\])?';
const VERSION = '[A-Za-z0-9.*+!_-]+';
const CLAUSE = `(?:===|==|!=|<=|>=|~=|<|>)\\s*${VERSION}`;
const CONSTRAINTS = `(?:\\s*\\(?\\s*${CLAUSE}(?:\\s*,\\s*${CLAUSE})*\\s*\\)?)?`;
const MARKER_VAR =
  '(?:python_version|python_full_version|os_name|sys_platform|platform_release|platform_system|platform_version|platform_machine|platform_python_implementation|implementation_name|implementation_version|extra)';
const MARKER_OP = '(?:===|==|!=|<=|>=|~=|<|>|not\\s+in|in)';
const MARKER_STR = `(?:"[A-Za-z0-9._ *+!-]{0,40}"|'[A-Za-z0-9._ *+!-]{0,40}')`;
const MARKER_ATOM = `\\(?\\s*(?:${MARKER_VAR}\\s*${MARKER_OP}\\s*${MARKER_STR}|${MARKER_STR}\\s*${MARKER_OP}\\s*${MARKER_VAR})\\s*\\)?`;
const MARKER = `(?:\\s*;\\s*${MARKER_ATOM}(?:\\s+(?:and|or)\\s+${MARKER_ATOM}){0,7})?`;
const SPEC_RE = new RegExp(`^${NAME}\\s*${EXTRAS}${CONSTRAINTS}${MARKER}$`);
const HASH_RE = /^--hash=sha(256|384|512):[a-fA-F0-9]{32,128}$/;

export const MAX_SPECS = 300;
const MAX_SPEC_LEN = 200;

export function isSafeSpec(spec: string): boolean {
  return spec.length > 0 && spec.length <= MAX_SPEC_LEN && !spec.startsWith('-') && !spec.includes('@') && SPEC_RE.test(spec);
}

export interface RequirementsResult {
  specs: string[];
  /** Set when the file(s) contain something we will not pass to pip. */
  rejected?: string;
  warnings: string[];
}

/** Paths a requirements file may include with -r (root or requirements/ only). */
export function isAllowedRequirementsPath(p: string): boolean {
  return /^(requirements\/)?[A-Za-z0-9._-]+\.txt$/.test(p) && !p.includes('..');
}

export function parseRequirements(
  entry: string,
  read: (path: string) => string | undefined,
  depth = 0,
  visited: Set<string> = new Set(),
): RequirementsResult {
  const result: RequirementsResult = { specs: [], warnings: [] };
  if (visited.has(entry)) return result;
  visited.add(entry);
  const text = read(entry);
  if (text === undefined) return { ...result, rejected: `${entry} could not be read (missing or too large)` };

  // Join backslash continuations, then process logical lines.
  const logical = text.replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  for (const rawLine of logical) {
    const line = rawLine.replace(/(^|\s)#.*$/, '').trim();
    if (line === '') continue;
    const tokens = line.split(/\s+/);
    const first = tokens[0] as string;

    if (first === '-r' || first === '--requirement' || first.startsWith('--requirement=') || (first.startsWith('-r') && first.length > 2)) {
      const target = first === '-r' || first === '--requirement' ? tokens[1] : first.replace(/^(--requirement=|-r)/, '');
      const base = entry.includes('/') ? entry.slice(0, entry.lastIndexOf('/') + 1) : '';
      const resolved = target ? `${base}${target}`.replace(/^\.\//, '') : '';
      if (!target || tokens.length > 2 || depth >= 3 || !isAllowedRequirementsPath(resolved)) {
        return { ...result, rejected: `unsupported include "${shorten(line)}"` };
      }
      const nested = parseRequirements(resolved, read, depth + 1, visited);
      if (nested.rejected) return { ...result, rejected: nested.rejected };
      result.specs.push(...nested.specs);
      result.warnings.push(...nested.warnings);
      continue;
    }
    if (first === '-c' || first === '--constraint' || first.startsWith('--constraint=')) {
      result.warnings.push('Constraint files (-c) are ignored.');
      continue;
    }
    if (first.startsWith('-')) return { ...result, rejected: `pip option "${shorten(line)}" is not allowed` };

    // Optional trailing --hash options on a spec line are dropped (hashes are not enforced).
    const specTokens: string[] = [];
    let sawHash = false;
    for (const t of tokens) {
      if (t.startsWith('--')) {
        if (!HASH_RE.test(t)) return { ...result, rejected: `pip option in "${shorten(line)}" is not allowed` };
        sawHash = true;
      } else {
        if (sawHash) return { ...result, rejected: `unexpected text in "${shorten(line)}"` };
        specTokens.push(t);
      }
    }
    const spec = specTokens.join(' ');
    if (!isSafeSpec(spec)) return { ...result, rejected: `requirement "${shorten(line)}" is not a plain package specifier` };
    if (sawHash && !result.warnings.includes('Hash pins are not enforced in the sandbox install.')) {
      result.warnings.push('Hash pins are not enforced in the sandbox install.');
    }
    result.specs.push(spec);
    if (result.specs.length > MAX_SPECS) return { ...result, rejected: `more than ${MAX_SPECS} requirements` };
  }
  return result;
}

function shorten(s: string): string {
  const cleaned = s.replace(/[^\x20-\x7e]/g, '?');
  return cleaned.length > 60 ? `${cleaned.slice(0, 59)}…` : cleaned;
}
