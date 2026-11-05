/**
 * Investigation reports. Every string that came from a repository or GitHub
 * is treated as hostile: Markdown control characters and HTML are escaped,
 * code is fenced with a fence longer than any backtick run it contains, and
 * links are only emitted for URLs this program built itself.
 */
import { BRAND } from '../brand.ts';
import type { Inspection } from '../runs/inspections.ts';
import type { AnalysisResult, Finding, Severity } from '../analysis/types.ts';
import { collapseControlChars } from '../text.ts';

export const REPORT_SCHEMA = 'unboxanyrepo.report/v1';

/** Escape untrusted inline text for Markdown (and any HTML-capable renderer). */
export function md(text: unknown, max = 500): string {
  let t = collapseControlChars(String(text ?? '')).replace(/\s+/g, ' ').trim();
  if (t.length > max) t = `${t.slice(0, max - 1)}…`;
  return t
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/([\\`*_{}[\]()#+!|~-])/g, '\\$1');
}

/** Fenced code block that untrusted content cannot break out of. */
export function fence(code: string, lang = ''): string {
  const clean = collapseControlChars(code.replace(/\r\n/g, '\n'), { keepNewlines: true });
  const longest = Math.max(2, ...[...clean.matchAll(/`+/g)].map((m) => m[0].length));
  const f = '`'.repeat(longest + 1);
  return `${f}${lang}\n${clean}\n${f}`;
}

/** Only https URLs to known hosts, built by this program, become links. */
function link(label: string, url: string): string {
  return /^https:\/\/(github\.com|osv\.dev|cwe\.mitre\.org|docs\.github\.com|docs\.docker\.com|docs\.npmjs\.com|securitylab\.github\.com|semgrep\.dev)\/[A-Za-z0-9/._~%+-]*(#[A-Za-z0-9._-]*)?$/.test(url) ? `[${md(label, 120)}](${url})` : `${md(label, 120)} (${md(url, 200)})`;
}

const SEV_LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

function findingMd(f: Finding): string {
  const loc = f.file ? `${md(f.file, 200)}${f.startLine ? `:${f.startLine}${f.endLine && f.endLine !== f.startLine ? `-${f.endLine}` : ''}` : ''}` : 'repository';
  const lines = [
    `#### ${md(f.title, 200)}`,
    '',
    `- **ID:** \`${f.id}\` (rule \`${f.ruleId.replace(/`/g, '')}\`)`,
    `- **Severity:** ${SEV_LABEL[f.severity]} · **Confidence:** ${f.confidence} · **Status:** ${f.status}`,
    `- **Location:** ${loc}`,
    `- **Detected by:** ${f.method}${f.cwe ? ` · ${f.cwe}` : ''}`,
  ];
  if (f.package) lines.push(`- **Package:** ${md(f.package.ecosystem)} ${md(f.package.name)} ${md(f.package.version)}${f.package.fixedIn?.length ? ` (fixed in ${md(f.package.fixedIn.join(', '))})` : ''}`);
  if (f.evidence) lines.push('', '**Evidence** (secrets redacted):', '', fence(f.evidence));
  lines.push('', `**Risk:** ${md(f.risk, 1200)}`, '', `**Recommendation:** ${md(f.remediation, 800)}`);
  if (f.references.length) lines.push('', `**References:** ${f.references.map((u) => link(u.replace(/^https:\/\//, ''), u)).join(' · ')}`);
  return lines.join('\n');
}

export function markdownReport(insp: Inspection, productName: string = BRAND.name, now = new Date()): string {
  const a: AnalysisResult = insp.analysis;
  const r = insp.repo;
  const out: string[] = [];
  const p = (...l: string[]) => out.push(...l);
  p(`# ${md(productName)} investigation report: ${md(r.fullName)}`, '');
  p(`- **Repository:** ${link(r.fullName, r.htmlUrl)}${insp.demo ? ' (bundled demo fixture)' : ''}`);
  p(`- **Commit:** \`${insp.commitSha}\` (${insp.commitSource === 'url' ? 'selected in the URL' : `head of ${md(r.defaultBranch)}`} at inspection time)`);
  p(`- **Generated:** ${now.toISOString()} by ${md(productName)} ${BRAND.version}`);
  p(`- **Files:** ${insp.source.fileCount.toLocaleString('en-US')} (${(insp.source.totalBytes / 1048576).toFixed(1)} MB); text analysed: ${a.coverage.textFiles.toLocaleString('en-US')} files${a.coverage.complete ? '' : ' (partial: some files were skipped, see Coverage)'}`);
  p('', `> ${md(a.disclaimer, 1000)}`, '');

  p('## Summary', '');
  p(`- **Project type:** ${md(a.launch.summary)}`);
  p(`- **Findings:** ${a.summary.total} (${(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((s) => `${a.summary.bySeverity[s]} ${s}`).join(', ')})`);
  p(`- **By status:** ${Object.entries(a.summary.byStatus).map(([k, v]) => `${v} ${k}`).join(', ')}`);
  p(`- **Preview:** ${a.launch.preview.kind === 'static' ? 'static preview available' : a.launch.preview.kind === 'build' ? 'needs a sandboxed build' : 'not available'}: ${md(a.launch.preview.reason, 400)}`);
  if (insp.notice) p(`- **Notice:** ${md(insp.notice, 400)}`);
  p('');

  p('## Analysis coverage and tools', '');
  p('Raw matches are counted before duplicates are merged and repeated matches in one file are grouped.', '');
  p('| Tool | Result | Raw matches | Notes |', '|---|---|---|---|');
  for (const t of a.tools) p(`| ${md(t.tool)}${t.version ? ` ${md(t.version)}` : ''} | ${t.state.replace('_', ' ')} | ${t.findings} | ${md(t.message ?? '', 300)} |`);
  const sk = a.coverage.skipped;
  p('', `Skipped files: ${Object.entries(sk).filter(([, v]) => v > 0).map(([k, v]) => `${v} ${k.replace('_', ' ')}`).join(', ') || 'none'}.`, '');

  p('## Technology stack', '');
  if (a.stack.length === 0) p('No frameworks or runtimes were identified from manifests.');
  for (const s of a.stack) p(`- **${md(s.name)}** (${s.kind}${s.version ? `, ${md(s.version, 60)}` : ''}) — ${md(s.evidence, 200)}`);
  p('', '**Languages by size:** ' + (a.structure.languages.map((l) => `${md(l.name)} ${l.percent}%`).join(', ') || 'none detected'), '');
  if (a.packageManagers.length) p('**Package managers:** ' + a.packageManagers.map((m) => `${md(m.name)} (${md(m.evidence, 120)})`).join('; '), '');

  p('## Structure', '');
  p(`${a.structure.fileCount} files in ${a.structure.dirCount} directories. Top level:`, '');
  p(fence(a.structure.topLevel.map((t) => `${t.kind === 'dir' ? `${t.name}/` : t.name}${t.kind === 'dir' ? `  (${t.files} files)` : ''}`).join('\n')));
  if (a.structure.entryPoints.length) {
    p('', '**Likely entry points:**', '');
    for (const e of a.structure.entryPoints) p(`- \`${e.path.replace(/`/g, '')}\` — ${md(e.reason, 200)}`);
  }
  p('');

  p('## Dependencies', '');
  p(`Manifests: ${a.manifests.map((m) => `${md(m.path, 120)} (${md(m.kind)})`).join(', ') || 'none'}.`, '');
  p(`Inventoried packages with exact versions: ${Object.entries(a.dependencies.byEcosystem).map(([k, v]) => `${v} ${md(k)}`).join(', ') || 'none'}.`);
  for (const n of a.dependencies.notes) p(`- ${md(n, 400)}`);
  p('');

  if (a.git.submodules.length) {
    p('## Git submodules', '', 'Submodule contents are not in GitHub source archives and were not analysed.', '', '| Name | Path | URL | Kind |', '|---|---|---|---|');
    for (const s of a.git.submodules) p(`| ${md(s.name, 80)} | ${s.path ? md(s.path, 120) : '—'} | ${s.url ? md(s.url, 200) : 'missing'} | ${s.urlKind} |`);
    p('');
  }
  if (a.git.lfs.pointerCount > 0) {
    p('## Git LFS files', '', `${a.git.lfs.pointerCount} pointer file${a.git.lfs.pointerCount === 1 ? '' : 's'}; ${(a.git.lfs.pointerBytes / 1048576).toFixed(1)} MB of content is fetched only by \`git lfs pull\` and was not analysed.`, '');
    for (const x of a.git.lfs.pointers.slice(0, 30)) p(`- ${md(x.path, 200)} (${(x.size / 1048576).toFixed(2)} MB)`);
    p('');
  }

  const scripts = a.scripts.filter((s) => s.kind !== 'other').slice(0, 40);
  if (scripts.length) {
    p('## Build, start and install scripts', '', '| Source | Name | Kind | Command |', '|---|---|---|---|');
    for (const s of scripts) p(`| ${md(s.source)} | ${md(s.name, 60)} | ${s.kind} | ${md(s.command, 200)} |`);
    p('');
  }
  if (a.dockerfiles.length || a.compose.length || a.ci.length) {
    p('## Containers and CI', '');
    for (const d of a.dockerfiles) p(`- **${md(d.path)}**: base ${d.baseImages.map((b) => md(b, 80)).join(', ') || 'unknown'}; exposes ${d.exposes.join(', ') || 'no ports'}; user ${d.user ? md(d.user, 40) : 'not set (root)'}`);
    for (const c of a.compose) p(`- **${md(c.path)}**: services ${c.services.map((s) => `${md(s.name)}${s.image ? ` (${md(s.image, 60)})` : s.build ? ' (built locally)' : ''}`).join(', ')}`);
    for (const c of a.ci) p(`- **${md(c.path)}** (${md(c.provider)}): jobs ${c.jobs.map((j) => md(j)).join(', ') || 'unknown'}${c.triggers.length ? `; triggers ${c.triggers.map((t) => md(t)).join(', ')}` : ''}`);
    p('');
  }
  if (a.env.length) {
    p('## Environment variables (names only)', '', '| Name | Documented | Seen in |', '|---|---|---|');
    for (const e of a.env.slice(0, 80)) p(`| \`${e.name}\` | ${e.documented ? 'yes' : 'no'} | ${e.sources.map((s) => md(s, 100)).join(', ')} |`);
    p('');
  }
  p('## Tests', '');
  p(`Frameworks: ${a.tests.frameworks.map((f) => md(f)).join(', ') || 'none detected'}. Test files: ${a.tests.testFiles}. Config: ${a.tests.configFiles.map((f) => md(f)).join(', ') || 'none'}.`);
  for (const c of a.tests.commands) p(`- \`${c.command}\` — ${md(c.source, 200)}`);
  p('');

  p('## How to run it locally', '');
  for (const w of a.launch.warnings) p(`> ${md(w, 400)}`, '>');
  if (a.launch.warnings.length) out.pop();
  p('');
  a.launch.steps.forEach((s, i) => {
    p(`${i + 1}. **${md(s.title)}**`);
    if (s.commands.length) p('', fence(s.commands.join('\n'), 'sh').split('\n').map((l) => `   ${l}`).join('\n'));
    if (s.note) p('', `   ${md(s.note, 600)}`);
    p('');
  });
  if (a.launch.ports.length) p(`Ports: ${a.launch.ports.map((x) => `${x.port} (${md(x.source, 80)})`).join(', ')}.`, '');
  if (a.launch.services.length) p(`Services: ${a.launch.services.map((x) => `${md(x.name)} (${md(x.source, 80)})`).join(', ')}.`, '');
  if (a.compatibility.length) {
    p('## Compatibility and setup notes', '');
    for (const c of a.compatibility) p(`- **${c.level}:** ${md(c.message, 500)}${c.evidence ? ` (${md(c.evidence, 120)})` : ''}`);
    p('');
  }

  p('## Security findings', '');
  if (a.findings.length === 0) p('No findings from the checks that ran. This does not mean the code has no vulnerabilities; see the disclaimer and coverage above.', '');
  for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as Severity[]) {
    const list = a.findings.filter((f) => f.severity === sev);
    if (!list.length) continue;
    p(`### ${SEV_LABEL[sev]} (${list.length})`, '');
    for (const f of list) p(findingMd(f), '');
  }
  if (a.advisories.length) {
    p('## Published repository advisories (GitHub)', '');
    for (const adv of a.advisories) p(`- ${link(adv.id, adv.url)} (${md(adv.severity)}): ${md(adv.summary, 300)}`);
    p('');
  }
  p('## Limitations', '');
  p('- Static analysis only: no repository code was executed to produce this report.');
  p('- Built-in and Semgrep rules are pattern-based and can miss issues or report false positives; "heuristic" findings need manual review.');
  p('- Secret matches are never tested against their issuers; "unverified" means the value may or may not be live.');
  p('- Dependency vulnerabilities are matched only for exact versions (lockfiles or == pins), using OSV.dev data available at generation time.');
  p('- Git submodules, Git LFS content and symbolic links are not part of the analysed snapshot.');
  p('');
  p(`Vulnerability data: [OSV.dev](https://osv.dev) and its upstream databases. Report schema ${REPORT_SCHEMA}.`);
  return `${out.join('\n')}\n`;
}

export function jsonReport(insp: Inspection, productName: string = BRAND.name, now = new Date()) {
  return {
    schema: REPORT_SCHEMA,
    generatedAt: now.toISOString(),
    tool: { name: productName, version: BRAND.version },
    repository: { fullName: insp.repo.fullName, url: insp.repo.htmlUrl, defaultBranch: insp.repo.defaultBranch, description: insp.repo.description, archived: insp.repo.archived, fork: insp.repo.fork },
    commit: { sha: insp.commitSha, source: insp.commitSource },
    demo: insp.demo,
    notice: insp.notice ?? null,
    source: insp.source,
    analysis: insp.analysis,
  };
}
