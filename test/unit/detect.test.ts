import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectProject } from '../../src/detect/index.ts';
import { sanitizeArchive } from '../../src/source/archive.ts';
import { parseRequirements, isSafeSpec } from '../../src/detect/requirements.ts';
import { CHECK_IDS } from '../../src/checks/types.ts';
import type { DetectionResult, CheckOption } from '../../src/checks/types.ts';
import { repoArchive } from '../helpers/tarbuilder.ts';
import { fixtures, oversizedPackageJson } from '../fixtures/detection.ts';
import type { RepoFixture } from '../fixtures/detection.ts';

const LIMITS = { maxCompressedBytes: 10e6, maxUncompressedBytes: 10e6, maxFiles: 1000, maxFileBytes: 2e6 };

async function detect(files: RepoFixture): Promise<DetectionResult> {
  const snap = await sanitizeArchive(repoArchive(files), LIMITS);
  return detectProject(snap, { goImage: 'golang:1.25-bookworm' });
}
const check = (r: DetectionResult, id: string): CheckOption => {
  const c = r.checks.find((x) => x.id === id);
  assert.ok(c, `missing check ${id}`);
  return c;
};

test('node: offers npm test/build with lockfile install and lifecycle scripts disabled', async () => {
  const r = await detect(fixtures.nodeBasic);
  assert.equal(r.status, 'checks_available');
  const t = check(r, 'node.npm-test');
  assert.equal(t.available, true);
  assert.equal(t.installsDependencies, true);
  assert.deepEqual(t.steps[0]?.argv.slice(0, 3), ['npm', 'ci', '--ignore-scripts']);
  assert.equal(t.steps[0]?.network, 'registry-proxy');
  assert.deepEqual(t.steps[1]?.argv, ['npm', 'test']);
  assert.equal(t.steps[1]?.network, 'none');
  assert.deepEqual(t.repoScripts, [{ source: 'package.json → scripts.test', text: 'node --test' }]);
  assert.equal(check(r, 'node.npm-build').available, true);
  assert.equal(check(r, 'node.npm-lint').available, false);
});

test('node: no dependencies means no install step and no network at all', async () => {
  const t = check(await detect(fixtures.nodeNoDeps), 'node.npm-test');
  assert.equal(t.installsDependencies, false);
  assert.equal(t.steps.length, 1);
  assert.ok(t.steps.every((s) => s.network === 'none'));
});

test('node: malformed, non-object, placeholder and oversized package.json yield no runnable checks', async () => {
  for (const f of [fixtures.nodeMalformed, fixtures.nodeArray, oversizedPackageJson()]) {
    const r = await detect(f);
    assert.equal(r.status, 'no_supported_checks');
    assert.equal(r.ecosystems[0]?.confidence, 'low');
    assert.ok(r.checks.every((c) => !c.available));
  }
  const p = await detect(fixtures.nodePlaceholder);
  assert.equal(check(p, 'node.npm-test').available, false);
});

test('node: yarn/pnpm projects are reported as unsupported package managers', async () => {
  for (const f of [fixtures.yarnProject, fixtures.pnpmField]) {
    const r = await detect(f);
    assert.equal(r.status, 'no_supported_checks');
    assert.match(check(r, 'node.npm-test').unavailableReason ?? '', /Only npm is supported/);
  }
});

test('node: adversarial package.json cannot pollute prototypes or inject commands', async () => {
  const r = await detect(fixtures.nodeAdversarial);
  const t = check(r, 'node.npm-test');
  assert.deepEqual(t.steps.at(-1)?.argv, ['npm', 'test']);
  const text = t.repoScripts[0]?.text ?? '';
  assert.equal(/[\u0000-\u001f]/.test(text), false, 'control characters removed');
  assert.ok(text.includes('<img'), 'kept as inert text (escaped by the UI)');
  assert.equal(check(r, 'node.npm-build').available, false, 'non-string script ignored');
  assert.equal(check(r, 'node.npm-lint').available, false);
  assert.equal(({} as Record<string, unknown>).scripts, undefined);
  // Every argv in every check is drawn from constants: no repository text leaks in.
  for (const c of r.checks) for (const s of c.steps) for (const a of s.argv) assert.equal(a.includes('evil'), false);
});

test('python: pytest plan installs wheels only, with validated specifiers', async () => {
  const r = await detect(fixtures.pythonPytest);
  const t = check(r, 'python.pytest');
  assert.equal(t.available, true);
  const install = t.steps[0];
  assert.ok(install);
  assert.ok(install.argv.includes('--only-binary=:all:'));
  assert.deepEqual(install.argv.slice(install.argv.indexOf('--index-url'), install.argv.indexOf('--index-url') + 2), ['--index-url', 'https://pypi.org/simple']);
  assert.ok(install.argv.includes('requests>=2.31'));
  assert.ok(install.argv.includes('pytest-cov'));
  assert.ok(!install.argv.includes('sphinx'), 'docs extras are not installed');
  assert.ok(install.argv.includes('pytest<9'));
  assert.equal(install.env.PIP_CONFIG_FILE, '/dev/null');
  assert.match(t.steps[1]?.env.PYTHONPATH ?? '', /\/work\/src\/src/);
  assert.equal(r.checks.some((c) => c.id === 'python.unittest'), false);
});

test('python: unittest plan when tests exist without pytest signals', async () => {
  const r = await detect(fixtures.pythonUnittest);
  const t = check(r, 'python.unittest');
  assert.equal(t.available, true);
  assert.deepEqual(t.steps.at(-1)?.argv, ['python', '-m', 'unittest', 'discover', '-v', '-s', 'tests', '-t', '.']);
  assert.ok(t.steps[0]?.argv.includes('six==1.16.0'));
});

test('python: -r includes and hash pins are handled', async () => {
  const r = await detect(fixtures.pythonReqIncludes);
  const t = check(r, 'python.pytest');
  assert.equal(t.available, true, t.unavailableReason ?? '');
  const argv = t.steps[0]?.argv ?? [];
  assert.ok(argv.includes('idna==3.6') && argv.includes('pytest==8.2.0'));
  assert.ok(!argv.includes('pytest<9'), 'project pins its own pytest');
  assert.ok(t.notes.some((n) => /Hash pins/.test(n)));
});

test('python: hostile requirements are rejected, never forwarded to pip', async () => {
  for (const name of [
    'pythonIndexInjection', 'pythonUrlReq', 'pythonEditable', 'pythonVcs', 'pythonDashSpec',
    'pythonIncludeEscape', 'pythonIncludeAbsolute', 'pythonMarkerInjection',
  ] as const) {
    const r = await detect(fixtures[name]);
    assert.equal(r.status, 'no_supported_checks', name);
    for (const c of r.checks) {
      assert.equal(c.available, false, name);
      for (const s of c.steps) for (const a of s.argv) assert.equal(/evil|index-url=https:\/\/evil|^-e$/.test(a), false, `${name}: ${a}`);
    }
  }
});

test('python: unreadable dependency formats are reported instead of guessed', async () => {
  for (const f of [fixtures.setupPyOnly, fixtures.poetryOnly, fixtures.pyprojectBroken, fixtures.loosePython]) {
    const r = await detect(f);
    assert.ok(r.checks.every((c) => !c.available));
    assert.equal(r.ecosystems[0]?.confidence, 'low');
  }
});

test('go: download step only when modules are required and not vendored', async () => {
  const basic = check(await detect(fixtures.goBasic), 'go.test');
  assert.deepEqual(basic.steps[0]?.argv, ['go', 'mod', 'download']);
  assert.equal(basic.steps[0]?.env.GOTOOLCHAIN, 'local');
  assert.equal(basic.steps[1]?.env.GOPROXY, 'off');
  const vend = check(await detect(fixtures.goVendored), 'go.test');
  assert.equal(vend.installsDependencies, false);
  assert.match(vend.steps[0]?.env.GOFLAGS ?? '', /-mod=vendor/);
  const none = check(await detect(fixtures.goNoDeps), 'go.test');
  assert.equal(none.steps.length, 1);
  for (const f of [fixtures.goModGarbage, fixtures.goModInjection]) {
    assert.ok((await detect(f)).checks.every((c) => !c.available));
  }
});

test('rust: fetch then offline test; path-only deps need no fetch; broken manifests are refused', async () => {
  const t = check(await detect(fixtures.rustBasic), 'rust.cargo-test');
  assert.deepEqual(t.steps[0]?.argv, ['cargo', 'fetch', '--locked']);
  assert.deepEqual(t.steps[1]?.argv, ['cargo', 'test', '--offline', '--locked']);
  const p = check(await detect(fixtures.rustPathOnly), 'rust.cargo-test');
  assert.equal(p.installsDependencies, false);
  for (const f of [fixtures.cargoBroken, fixtures.cargoNoPackage]) {
    assert.ok((await detect(f)).checks.every((c) => !c.available));
  }
});

test('ambiguous and unsupported repositories', async () => {
  const multi = await detect(fixtures.multiEcosystem);
  assert.deepEqual(multi.ecosystems.map((e) => e.ecosystem).sort(), ['go', 'node']);
  assert.ok(multi.warnings.some((w) => /More than one ecosystem/.test(w)));
  const un = await detect(fixtures.unsupported);
  assert.equal(un.status, 'unsupported');
  assert.ok(un.unsupportedSignals.includes('Java (Maven)'));
  assert.ok(un.unsupportedSignals.some((s) => s.startsWith('Makefile')));
  assert.equal(un.checks.length, 0);
  assert.equal((await detect(fixtures.empty)).status, 'unsupported');
  const mono = await detect(fixtures.monorepo);
  assert.equal(mono.status, 'unsupported');
  assert.ok(mono.warnings.some((w) => /Nested project manifests/.test(w)));
});

test('every generated check uses an allowlisted id and a constant executable', async () => {
  const allowedExecutables = new Set(['npm', 'python', 'go', 'cargo']);
  for (const f of Object.values(fixtures)) {
    const r = await detect(f);
    for (const c of r.checks) {
      assert.ok((CHECK_IDS as readonly string[]).includes(c.id));
      for (const s of c.steps) {
        assert.ok(allowedExecutables.has(s.argv[0] ?? ''), s.argv.join(' '));
        for (const v of Object.values(s.env)) assert.equal(/[\n\r\0]/.test(v), false);
      }
    }
  }
});

test('requirement specifier validation', () => {
  for (const ok of ['requests', 'requests==2.31.0', 'attrs[tests]>=23,<24', 'x~=1.4.2', 'pkg ; python_version < "3.11"', 'A.B-c_d===1.0']) {
    assert.equal(isSafeSpec(ok), true, ok);
  }
  for (const bad of ['-e .', '--index-url=x', 'x @ https://e', 'git+https://x', './local', '/abs/path', 'x==1; os.system("x")', 'x==1 ; python_version>"3" @ y', '', 'x'.repeat(300)]) {
    assert.equal(isSafeSpec(bad), false, bad);
  }
  const files: Record<string, string> = { 'a.txt': '-r b.txt\nx==1', 'b.txt': '-r a.txt\ny==2' };
  const res = parseRequirements('a.txt', (p) => files[p]);
  assert.deepEqual(res.specs.sort(), ['x==1', 'y==2'], 'include cycles terminate');
});
