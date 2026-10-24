/**
 * Scanner adapters. Parser tests always run. The integration test runs the
 * real Semgrep/Gitleaks binaries when they are installed and is skipped with
 * an explicit reason otherwise (it is never reported as passed).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSemgrep, parseGitleaks, scannerVersion, runScanners } from '../../src/analysis/scanners.ts';
import { SourceView } from '../../src/analysis/source.ts';

test('Semgrep output is mapped to findings; paths stay inside the scan root', () => {
  const json = {
    results: [
      { check_id: 'rules.semgrep.uar.py.os-system-dynamic', path: '/tmp/x/src/app.py', start: { line: 4 }, end: { line: 4 }, extra: { message: 'os.system with a dynamic command. Use subprocess.', severity: 'ERROR', lines: 'requires login', metadata: { cwe: 'CWE-78: OS Command Injection', category: 'command-injection', confidence: 'MEDIUM' } } },
      { check_id: 'x', path: '/etc/passwd', start: { line: 1 }, extra: {} },
    ],
  };
  const out = parseSemgrep(json, '/tmp/x/src', (f, l) => (f === 'app.py' && l === 4 ? 'os.system(cmd)' : undefined));
  assert.equal(out.length, 1);
  const f = out[0]!;
  assert.equal(f.ruleId, 'semgrep.uar.py.os-system-dynamic');
  assert.equal(f.file, 'app.py');
  assert.equal(f.severity, 'high');
  assert.equal(f.status, 'heuristic');
  assert.equal(f.cwe, 'CWE-78');
  assert.equal(f.evidence, 'os.system(cmd)');
  assert.throws(() => parseSemgrep({ nope: 1 }, '/tmp'), /unexpected/);
});

test('Gitleaks output never copies the matched value; generic matches are downgraded', () => {
  const out = parseGitleaks(
    [
      { RuleID: 'github-pat', Description: 'GitHub PAT', File: '/s/src/config.js', StartLine: 3, EndLine: 3, Match: 'token=ghp_REAL', Secret: 'ghp_REAL' },
      { RuleID: 'generic-api-key', Description: 'Generic', File: '/s/src/docs/a.json', StartLine: 9, Match: 'k=abc', Secret: 'abc' },
    ],
    '/s/src',
  );
  assert.equal(out.length, 2);
  assert.ok(!JSON.stringify(out).includes('ghp_REAL'));
  assert.equal(out[0]?.severity, 'high');
  assert.equal(out[0]?.status, 'unverified');
  assert.equal(out[1]?.severity, 'low');
  assert.equal(out[1]?.status, 'heuristic');
});

test('missing scanners are reported as not installed, not as clean', async () => {
  const src = new SourceView({ files: [{ path: 'a.py', size: 3 }], dirs: [], texts: new Map([['a.py', Buffer.from('x=1')]]), totalBytes: 3 });
  const r = await runScanners(src, { scanners: ['semgrep', 'gitleaks'], semgrepBin: '/nonexistent/semgrep', gitleaksBin: '/nonexistent/gitleaks', osv: false, githubAdvisories: false }, 5000);
  assert.deepEqual(r.tools.map((t) => t.state), ['not_installed', 'not_installed']);
  const off = await runScanners(src, { scanners: 'off', semgrepBin: 'semgrep', gitleaksBin: 'gitleaks', osv: false, githubAdvisories: false }, 5000);
  assert.deepEqual(off.tools.map((t) => t.state), ['disabled', 'disabled']);
});

const semgrep = await scannerVersion('semgrep', 'semgrep');
const gitleaks = await scannerVersion('gitleaks', 'gitleaks');

test('real Semgrep and Gitleaks run against harmless sample files', { skip: semgrep && gitleaks ? false : 'semgrep and/or gitleaks are not installed (NOT RUN)', timeout: 180_000 }, async () => {
  const fakeToken = `ghp_${'q7W2e9R4t1Y6u3I8o5P0'.repeat(2).slice(0, 36)}`;
  const texts = new Map<string, Buffer>([
    ['app.py', Buffer.from('import os\nimport pickle\n\ndef run(cmd):\n    os.system("echo " + cmd)\n    return pickle.loads(cmd)\n')],
    ['config.js', Buffer.from(`module.exports = { token: "${fakeToken}" };\n`)],
    ['../escape.py', Buffer.from('os.system(x)')],
  ]);
  const src = new SourceView({ files: [...texts.keys()].map((p) => ({ path: p, size: 1 })), dirs: [], texts, totalBytes: 100 });
  const r = await runScanners(src, { scanners: 'auto', semgrepBin: 'semgrep', gitleaksBin: 'gitleaks', osv: false, githubAdvisories: false }, 150_000);
  const sg = r.tools.find((t) => t.tool === 'Semgrep');
  const gl = r.tools.find((t) => t.tool === 'Gitleaks');
  assert.equal(sg?.state, 'ran', sg?.message ?? '');
  assert.equal(gl?.state, 'ran', gl?.message ?? '');
  const ids = r.findings.map((f) => f.ruleId);
  assert.ok(ids.includes('semgrep.uar.py.os-system-dynamic'), ids.join(','));
  assert.ok(ids.includes('semgrep.uar.py.unsafe-deserialization'), ids.join(','));
  assert.ok(r.findings.some((f) => f.method === 'gitleaks' && f.file === 'config.js'), ids.join(','));
  assert.ok(!JSON.stringify(r.findings).includes(fakeToken));
  assert.ok(r.findings.every((f) => !f.file?.includes('..')), 'nothing written outside the scan directory');
});
