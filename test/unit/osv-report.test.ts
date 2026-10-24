import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkOsv, cvss3BaseScore, osvSeverity } from '../../src/analysis/osv.ts';
import { safeFetch, FetchError } from '../../src/github/fetcher.ts';
import type { Transport, TransportResponse } from '../../src/github/fetcher.ts';
import type { DependencyPackage } from '../../src/analysis/types.ts';
import { md, fence, markdownReport, jsonReport } from '../../src/report/report.ts';
import { sanitizeArchive } from '../../src/source/archive.ts';
import { textSkipReason, looksBinary, isSecondaryText } from '../../src/analysis/paths.ts';
import { repoArchive } from '../helpers/tarbuilder.ts';
import { analyseOffline } from '../helpers/analysis.ts';
import { InspectionStore } from '../../src/runs/inspections.ts';
import { detectProject } from '../../src/detect/index.ts';

function respond(status: number, body: unknown, headers: Record<string, string> = {}): TransportResponse {
  const buf = Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  return { status, headers, body: (async function* () { yield buf; })(), destroy() {} };
}

const pkgs: DependencyPackage[] = [
  { ecosystem: 'npm', name: 'lodash', version: '4.17.20', exact: true, source: 'package-lock.json' },
  { ecosystem: 'npm', name: 'left-pad', version: '1.3.0', exact: true, source: 'package-lock.json' },
  { ecosystem: 'PyPI', name: 'flask', version: '>=2', exact: false, source: 'requirements.txt' },
];

test('CVSS v3 base scores match the specification examples', () => {
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(cvss3BaseScore('CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'), 5.5);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3BaseScore('CVSS:2.0/whatever'), undefined);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:X/AC:L'), undefined);
  assert.equal(osvSeverity({ id: 'x', database_specific: { severity: 'MODERATE' } }), 'medium');
  assert.equal(osvSeverity({ id: 'x', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }), 'critical');
  assert.equal(osvSeverity({ id: 'x' }), undefined);
});

test('OSV lookup: only exact versions are queried; results become confirmed findings with fixes', async () => {
  const seen: { url: string; body?: string }[] = [];
  const transport: Transport = async (url, _h, _s, body) => {
    seen.push({ url: url.toString(), ...(body ? { body: body.toString() } : {}) });
    if (url.pathname === '/v1/querybatch') return respond(200, { results: [{ vulns: [{ id: 'GHSA-29mw-wpgm-hmr9', modified: 'x' }] }, {}] });
    if (url.pathname === '/v1/vulns/GHSA-29mw-wpgm-hmr9') {
      return respond(200, {
        id: 'GHSA-29mw-wpgm-hmr9',
        summary: 'Regular Expression Denial of Service in lodash',
        details: 'Long <b>details</b>',
        aliases: ['CVE-2020-28500'],
        database_specific: { severity: 'MODERATE' },
        affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
        references: [{ url: 'https://github.com/advisories/GHSA-29mw-wpgm-hmr9' }, { url: 'javascript:alert(1)' }],
      });
    }
    return respond(404, {});
  };
  const { findings, tool } = await checkOsv(pkgs, { userAgent: 't', timeoutMs: 5000, transport });
  assert.equal(tool.state, 'ran');
  const batch = JSON.parse(seen[0]?.body ?? '{}');
  assert.equal(batch.queries.length, 2, 'the version range is not queried');
  assert.equal(seen[0]?.url, 'https://api.osv.dev/v1/querybatch');
  assert.equal(findings.length, 1);
  const f = findings[0]!;
  assert.equal(f.status, 'confirmed');
  assert.equal(f.severity, 'medium');
  assert.equal(f.method, 'osv');
  assert.deepEqual(f.package?.fixedIn, ['4.17.21']);
  assert.match(f.remediation, /Upgrade lodash to 4\.17\.21/);
  assert.ok(f.references.every((r) => r.startsWith('https://')), 'non-https references dropped');
  assert.match(f.evidence ?? '', /CVE-2020-28500/);
});

test('OSV lookup: failures are reported, never turned into "no vulnerabilities"', async () => {
  const transport: Transport = async () => respond(500, 'boom');
  const r = await checkOsv(pkgs, { userAgent: 't', timeoutMs: 5000, transport });
  assert.equal(r.tool.state, 'failed');
  assert.equal(r.findings.length, 0);
  assert.match(r.tool.message ?? '', /were not checked/);
  const none = await checkOsv([pkgs[2]!], { userAgent: 't', timeoutMs: 5000, transport });
  assert.equal(none.tool.state, 'skipped');
});

test('safe fetcher: POST bodies are sent but redirects are refused; hosts stay allowlisted', async () => {
  let gotBody = '';
  const transport: Transport = async (_u, _h, _s, body) => {
    gotBody = body?.toString() ?? '';
    return respond(302, '', { location: 'https://evil.example/x' });
  };
  await assert.rejects(
    safeFetch('https://api.osv.dev/v1/querybatch', { allowedHosts: new Set(['api.osv.dev']), body: Buffer.from('{"a":1}'), maxBytes: 1000, timeoutMs: 1000, transport }),
    (e: unknown) => e instanceof FetchError && e.code === 'redirect_not_allowed',
  );
  assert.equal(gotBody, '{"a":1}');
  await assert.rejects(safeFetch('https://169.254.169.254/latest', { allowedHosts: new Set(['api.osv.dev']), body: Buffer.from('x'), maxBytes: 10, timeoutMs: 1000, transport }), FetchError);
});

test('Markdown escaping: repository text cannot inject links, HTML or break code fences', () => {
  assert.equal(md('[click](javascript:alert(1))'), '\\[click\\]\\(javascript:alert\\(1\\)\\)');
  assert.equal(md('<img src=x onerror=1>'), '&lt;img src=x onerror=1&gt;');
  assert.equal(md('line1\nline2\u0007'), 'line1 line2');
  const f = fence('a ``` b ```` c');
  assert.ok(f.startsWith('`````\n') && f.endsWith('\n`````'));
});

test('reports: Markdown and JSON are generated from the analysis, pinned to the commit, with secrets redacted', async () => {
  const files = {
    'package.json': JSON.stringify({ description: 'x', scripts: { start: 'node s.js' }, dependencies: { express: '4.0.0' } }),
    's.js': `const k = "ghp_${'Z'.repeat(36)}";\napp.listen(3000)`,
    'README.md': '# [evil](javascript:alert(1))',
  };
  const snap = await sanitizeArchive(repoArchive(files), { maxCompressedBytes: 1e7, maxUncompressedBytes: 1e7, maxFiles: 100, maxFileBytes: 1e6 }, {
    collectText: { maxTotalBytes: 1e6, maxSecondaryBytes: 1e5, isSecondary: isSecondaryText, skipReason: (p, s) => textSkipReason(p, s, 1e5), isBinary: looksBinary },
  });
  const store = new InspectionStore({ ttlSec: 60 });
  const insp = store.add({
    sessionId: 's',
    repo: { owner: 'o', name: 'r', fullName: 'o/r', description: 'desc [x](javascript:y)', defaultBranch: 'main', language: 'JavaScript', htmlUrl: 'https://github.com/o/r', sizeKiB: 1, archived: false, fork: false },
    commitSha: 'b'.repeat(40),
    commitSource: 'default_branch',
    demo: false,
    notice: undefined,
    source: { fileCount: snap.files.length, totalBytes: snap.totalBytes, skippedSymlinkCount: 0, skippedSymlinks: [] },
    detection: detectProject(snap, { goImage: 'golang:1.25' }),
    analysis: await analyseOffline(snap, { fullName: 'o/r', htmlUrl: 'https://github.com/o/r', name: 'r' }, 'b'.repeat(40)),
    sanitizedTarGz: snap.sanitizedTarGz,
  });
  const text = markdownReport(insp, 'UnboxAnyRepo', new Date('2026-01-01T00:00:00Z'));
  assert.match(text, /^# UnboxAnyRepo investigation report: o\/r/);
  assert.match(text, new RegExp(`\\*\\*Commit:\\*\\* \`${'b'.repeat(40)}\``));
  assert.match(text, /## Security findings/);
  assert.match(text, /GitHub token/);
  assert.match(text, /cannot prove that code is safe/);
  assert.ok(!text.includes('Z'.repeat(36)), 'secret value not in the report');
  assert.ok(!/\]\(javascript:/.test(text), 'no injected javascript: links');
  assert.match(text, /npm ci --ignore-scripts|npm install --ignore-scripts/);
  const json = jsonReport(insp, 'UnboxAnyRepo', new Date('2026-01-01T00:00:00Z'));
  assert.equal(json.schema, 'unboxanyrepo.report/v1');
  assert.equal(json.commit.sha, 'b'.repeat(40));
  assert.ok(!JSON.stringify(json).includes('Z'.repeat(36)));
  assert.ok(json.analysis.findings.length > 0);
});

test('OSV: aliases of one vulnerability are reported once; Git commit "fixes" are not versions', async () => {
  const transport: Transport = async (url) => {
    if (url.pathname === '/v1/querybatch') return respond(200, { results: [{ vulns: [{ id: 'PYSEC-2023-62' }, { id: 'GHSA-m2qf-hxjv-5gpq' }] }] });
    if (url.pathname === '/v1/vulns/PYSEC-2023-62') return respond(200, { id: 'PYSEC-2023-62', aliases: ['GHSA-m2qf-hxjv-5gpq', 'CVE-2023-30861'], affected: [{ package: { name: 'flask', ecosystem: 'PyPI' }, ranges: [{ type: 'GIT', events: [{ fixed: '70f906c51ce49c485f1d355703e9cc3386b1cc2b' }] }, { type: 'ECOSYSTEM', events: [{ fixed: '2.2.5' }] }] }] });
    if (url.pathname === '/v1/vulns/GHSA-m2qf-hxjv-5gpq') return respond(200, { id: 'GHSA-m2qf-hxjv-5gpq', summary: 'Flask session cookie disclosure', aliases: ['CVE-2023-30861'], database_specific: { severity: 'HIGH' }, affected: [{ package: { name: 'flask', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.2.5' }, { fixed: '2.3.2' }] }] }] });
    return respond(404, {});
  };
  const { findings } = await checkOsv([{ ecosystem: 'PyPI', name: 'flask', version: '2.0.1', exact: true, source: 'requirements.txt' }], { userAgent: 't', timeoutMs: 5000, transport });
  assert.equal(findings.length, 1);
  assert.match(findings[0]!.title, /session cookie disclosure/);
  assert.equal(findings[0]!.severity, 'high');
  assert.deepEqual(findings[0]!.package?.fixedIn, ['2.2.5', '2.3.2']);
  const ghsaOnly = await checkOsv([{ ecosystem: 'PyPI', name: 'flask', version: '2.0.1', exact: true, source: 'r' }], {
    userAgent: 't', timeoutMs: 5000,
    transport: async (url) => url.pathname === '/v1/querybatch' ? respond(200, { results: [{ vulns: [{ id: 'PYSEC-2023-62' }] }] }) : transport(url, {}, new AbortController().signal),
  });
  assert.deepEqual(ghsaOnly.findings[0]!.package?.fixedIn, ['2.2.5'], 'GIT commit hashes are dropped');
});
