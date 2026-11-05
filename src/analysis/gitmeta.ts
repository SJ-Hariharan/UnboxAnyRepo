/**
 * Git metadata that GitHub source archives leave out: submodules (only
 * .gitmodules is included, not their contents) and Git LFS objects (only small
 * pointer files are included). Reads text only; never contacts the URLs found.
 */
import type { SourceView } from './source.ts';
import type { Finding, GitMetaSummary, LfsPointer, SubmoduleInfo, SubmoduleUrlKind } from './types.ts';
import { make, excerpt } from './rules/finding.ts';
import { collapseControlChars } from '../text.ts';

const MAX_SUBMODULES = 100;
const MAX_POINTERS = 200;
const LFS_RE = /^version https:\/\/git-lfs\.github\.com\/spec\/v1\r?\noid sha256:([a-f0-9]{64})\r?\nsize (\d{1,15})\r?\n?/;

/** Classify a submodule URL without contacting it. */
export function classifySubmoduleUrl(url: string): SubmoduleUrlKind {
  const u = url.trim();
  if (u.startsWith('-')) return 'option-like';
  if (/^ext::/i.test(u)) return 'ext-transport';
  if (/^(\.\.?\/)/.test(u)) return 'relative';
  if (/^file:/i.test(u) || /^\//.test(u) || /^[A-Za-z]:[\\/]/.test(u)) return 'local';
  if (/^https:\/\//i.test(u)) return 'https';
  if (/^http:\/\//i.test(u)) return 'http';
  if (/^git:\/\//i.test(u)) return 'git-protocol';
  if (/^ssh:\/\//i.test(u) || /^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:/.test(u)) return 'ssh';
  return 'other';
}

/** Parse .gitmodules (git-config syntax). Keys are case-insensitive; values may be quoted. */
export function parseGitmodules(text: string): { name: string; path?: string; url?: string; branch?: string; line: number }[] {
  const out: { name: string; path?: string; url?: string; branch?: string; line: number }[] = [];
  let cur: (typeof out)[number] | undefined;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length && out.length < MAX_SUBMODULES; i++) {
    const raw = (lines[i] as string).replace(/^\s+/, '');
    if (raw === '' || raw.startsWith('#') || raw.startsWith(';')) continue;
    const sec = /^\[\s*submodule\s+"([^"]{1,200})"\s*\]/i.exec(raw);
    if (sec) {
      cur = { name: sec[1] as string, line: i + 1 };
      out.push(cur);
      continue;
    }
    if (raw.startsWith('[')) {
      cur = undefined;
      continue;
    }
    const kv = /^([A-Za-z][A-Za-z0-9-]*)\s*=\s*(.*)$/.exec(raw);
    if (!kv || !cur) continue;
    let value = (kv[2] as string).replace(/\s+[#;].*$/, '').trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    value = collapseControlChars(value).slice(0, 300);
    const key = (kv[1] as string).toLowerCase();
    if (key === 'path' || key === 'url' || key === 'branch') cur[key] = value;
  }
  return out;
}

export function analyseGitMeta(src: SourceView): { summary: GitMetaSummary; findings: Finding[] } {
  const findings: Finding[] = [];
  const submodules: SubmoduleInfo[] = [];
  const gm = src.text('.gitmodules');
  if (gm !== undefined) {
    for (const s of parseGitmodules(gm)) {
      const kind = s.url !== undefined ? classifySubmoduleUrl(s.url) : 'missing';
      // The archive cannot say which commit a submodule is pinned to, or whether its folder exists in the tree.
      submodules.push({ name: s.name, ...(s.path !== undefined ? { path: s.path } : {}), ...(s.url !== undefined ? { url: s.url } : {}), ...(s.branch !== undefined ? { branch: s.branch } : {}), urlKind: kind, line: s.line });
      const f = submoduleFinding(s, kind, gm);
      if (f) findings.push(f);
    }
  }

  const pointers: LfsPointer[] = [];
  let pointerCount = 0;
  let pointerBytes = 0;
  for (const p of src.textPaths()) {
    const t = src.text(p);
    if (t === undefined || t.length > 300 || !t.startsWith('version https://git-lfs')) continue;
    const m = LFS_RE.exec(t);
    if (!m) continue;
    pointerCount++;
    const size = Number(m[2]);
    pointerBytes += size;
    if (pointers.length < MAX_POINTERS) pointers.push({ path: p, size });
  }
  pointers.sort((a, b) => b.size - a.size || a.path.localeCompare(b.path));
  const attrs = src.text('.gitattributes');
  const lfsPatterns = attrs
    ? attrs
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => !l.startsWith('#') && /\sfilter=lfs(\s|$)/.test(l))
        .map((l) => excerpt(l.split(/\s+/)[0] as string, 120))
        .slice(0, 50)
    : [];

  return {
    summary: { submodules, lfs: { patterns: lfsPatterns, pointers, pointerCount, pointerBytes } },
    findings,
  };
}

function submoduleFinding(s: { name: string; url?: string; line: number }, kind: SubmoduleUrlKind, text: string): Finding | undefined {
  const url = s.url ?? '';
  const evidence = `submodule "${excerpt(s.name, 60)}" url = ${excerpt(url, 140)}`;
  const line = urlLine(text, s.line);
  const base = { category: 'configuration' as const, file: '.gitmodules', startLine: line, evidence, method: 'manifest-analysis' as const };
  switch (kind) {
    case 'option-like':
      return make('GIT', {
        ...base,
        ruleId: 'git.submodule-url-option',
        title: 'Submodule URL starts with "-"',
        severity: 'high',
        confidence: 'high',
        status: 'confirmed',
        risk: 'Old Git versions passed such URLs to ssh as command-line options, which allowed command execution on "git clone --recurse-submodules" (CVE-2017-1000117). There is no legitimate reason for a URL to start with "-".',
        remediation: 'Do not clone this repository recursively. Keep Git up to date. Inspect .gitmodules before running any submodule command.',
        references: ['https://nvd.nist.gov/vuln/detail/CVE-2017-1000117'],
        cwe: 'CWE-88',
      });
    case 'ext-transport':
      return make('GIT', {
        ...base,
        ruleId: 'git.submodule-ext-transport',
        title: 'Submodule uses the ext:: transport',
        severity: 'high',
        confidence: 'high',
        status: 'confirmed',
        risk: 'The ext:: transport runs an arbitrary command to fetch the submodule. Git blocks it by default (protocol.allow), but a changed configuration would run that command on "git submodule update".',
        remediation: 'Do not initialise this submodule. Keep protocol.ext.allow at its default ("never").',
        references: ['https://git-scm.com/docs/git-remote-ext', 'https://git-scm.com/docs/git-config#Documentation/git-config.txt-protocolallow'],
        cwe: 'CWE-78',
      });
    case 'local':
      return make('GIT', {
        ...base,
        ruleId: 'git.submodule-local-path',
        title: 'Submodule points to a local path',
        severity: 'medium',
        confidence: 'high',
        status: 'confirmed',
        risk: 'A local or file: URL refers to a path on the machine that clones the repository. It will not work for others, and recursive clones of local paths have been involved in Git vulnerabilities (for example CVE-2022-39253).',
        remediation: 'Replace it with a public https:// URL, or skip this submodule.',
        references: ['https://github.blog/open-source/git/git-security-vulnerabilities-announced-2/'],
        cwe: 'CWE-59',
      });
    case 'http':
    case 'git-protocol':
      return make('GIT', {
        ...base,
        ruleId: 'git.submodule-insecure-transport',
        title: `Submodule is fetched over unencrypted ${kind === 'http' ? 'http://' : 'git://'}`,
        severity: 'medium',
        confidence: 'high',
        status: 'confirmed',
        risk: 'Anyone on the network path can replace the submodule\'s code during clone, and the main repository would build it.',
        remediation: 'Change the URL to https://.',
        references: ['https://git-scm.com/book/en/v2/Git-on-the-Server-The-Protocols'],
        cwe: 'CWE-319',
      });
    case 'ssh':
      return make('GIT', {
        ...base,
        ruleId: 'git.submodule-ssh',
        title: 'Submodule needs SSH access',
        severity: 'info',
        confidence: 'high',
        status: 'informational',
        risk: 'Cloning it needs an SSH key with access to that host. Anonymous clones and CI without keys will fail.',
        remediation: 'Prefer an https:// URL for public submodules.',
        references: [],
      });
    default:
      return undefined;
  }
}

/** Line of the submodule's url key, falling back to its section header. */
function urlLine(text: string, headerLine: number): number {
  const lines = text.split(/\r?\n/);
  for (let i = headerLine; i < lines.length; i++) {
    const l = (lines[i] as string).trim();
    if (l.startsWith('[')) break;
    if (/^url\s*=/i.test(l)) return i + 1;
  }
  return headerLine;
}
