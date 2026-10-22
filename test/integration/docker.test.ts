/**
 * Real-container tests for the Docker runner. Skipped unless
 * REPORADAR_TEST_DOCKER=1. Configure like production:
 *
 *   REPORADAR_TEST_DOCKER=1 REPORADAR_DOCKER_RUNTIME=runsc \
 *   REPORADAR_IMAGE_NODE=... REPORADAR_IMAGE_PYTHON=... REPORADAR_IMAGE_GO=... \
 *   npm run test:docker
 *
 * With REPORADAR_DOCKER_RUNTIME=runc you must also set
 * REPORADAR_ALLOW_UNSAFE_LOCAL_RUNNER (development only).
 */
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { loadConfig } from '../../src/config.ts';
import type { Config, Ecosystem } from '../../src/config.ts';
import { createRunner } from '../../src/runner/factory.ts';
import type { Runner, ExecuteResult } from '../../src/runner/types.ts';
import { FixtureGitHubClient } from '../../src/demo/fixtures.ts';
import { sanitizeArchive } from '../../src/source/archive.ts';
import { detectProject } from '../../src/detect/index.ts';
import type { StepPlan, CheckId } from '../../src/checks/types.ts';
import { RunLog } from '../../src/runs/logs.ts';
import { ROOT } from '../helpers/server.ts';

const enabled = process.env.REPORADAR_TEST_DOCKER === '1';
const skip = enabled ? false : 'set REPORADAR_TEST_DOCKER=1 to run real-container tests';
const github = new FixtureGitHubClient(path.join(ROOT, 'fixtures', 'demo-repos'));
const LIM = { maxCompressedBytes: 1e7, maxUncompressedBytes: 1e7, maxFiles: 1000, maxFileBytes: 1e6 };

function cfg(over: Record<string, string> = {}): Config {
  return loadConfig({ ...process.env, REPORADAR_RUNNER: 'docker', ...over });
}

async function fixture(name: string) {
  const meta = await github.getRepo('reporadar-demo', name);
  const sha = await github.resolveBranch(meta);
  const snap = await sanitizeArchive(await github.downloadArchive(meta, sha), LIM);
  return { snap, detection: detectProject(snap, { goImage: 'golang:1.25' }) };
}

async function exec(runner: Runner, ecosystem: Ecosystem, steps: StepPlan[], source: Buffer, opts: { signal?: AbortSignal; log?: RunLog } = {}) {
  const log = opts.log ?? new RunLog({ headBytes: 1024 * 1024, tailBytes: 64 * 1024 });
  const res: ExecuteResult = await runner.execute({
    ecosystem,
    steps,
    source,
    signal: opts.signal ?? new AbortController().signal,
    onPhase: () => {},
    onOutput: (s, c) => log.write(s, c),
    onOutputEnd: (s) => log.end(s),
    onSystem: (t) => log.system(t),
  });
  return { res, text: log.toText(), log };
}

async function runCheck(name: string, id: CheckId) {
  const { snap, detection } = await fixture(name);
  const check = detection.checks.find((c) => c.id === id);
  assert.ok(check?.available, `${name}: ${id} not available`);
  return exec(createRunner(cfg()), check.ecosystem, check.steps, snap.sanitizedTarGz);
}

/** A raw probe step (tests only — the API never accepts commands). */
function probe(argv: string[]): StepPlan {
  return { kind: 'check', title: 'probe', argv, env: { HOME: '/work/.home', TMPDIR: '/work/.home/tmp' }, network: 'none' };
}

function leftovers(): string {
  const c = execFileSync('docker', ['ps', '-a', '-q', '--filter', 'label=reporadar.managed=1']).toString().trim();
  const v = execFileSync('docker', ['volume', 'ls', '-q', '--filter', 'label=reporadar.managed=1']).toString().trim();
  return `${c}${v}`;
}

let nodeSource: Buffer;
before(async () => {
  if (enabled) nodeSource = (await fixture('node-hello')).snap.sanitizedTarGz;
});

test('runner reports itself available with the configured isolation', { skip }, async () => {
  const status = await createRunner(cfg()).status();
  assert.equal(status.available, true, status.reason ?? "");
  assert.equal(status.isolation, cfg().runner.runtime === 'runsc' ? 'strong' : 'unsafe-local');
});

test('node fixture: npm test passes', { skip }, async () => {
  const { res, text } = await runCheck('node-hello', 'node.npm-test');
  assert.equal(res.outcome, 'succeeded', text);
  assert.match(text, /pass 2/);
  assert.equal(res.cleanup, 'confirmed');
});

test('node fixture with a failing test reports failure and the exit code', { skip }, async () => {
  const { res, text } = await runCheck('node-failing', 'node.npm-test');
  assert.equal(res.outcome, 'failed', text);
  assert.equal(res.failedStep, 'check');
  assert.notEqual(res.exitCode, 0);
  assert.match(text, /floating point says no/);
});

test('python fixture: unittest passes', { skip }, async () => {
  const { res, text } = await runCheck('python-hello', 'python.unittest');
  assert.equal(res.outcome, 'succeeded', text);
  assert.match(text, /Ran 2 tests/);
});

test('go fixture: go test passes offline', { skip }, async () => {
  const { res, text } = await runCheck('go-hello', 'go.test');
  assert.equal(res.outcome, 'succeeded', text);
  assert.match(text, /ok\s+example\.com\/gohello/);
});

test('sandbox properties: non-root, no network, read-only root, clean env, workspace only', { skip }, async () => {
  const script = `
    const net = require('node:net'); const fs = require('node:fs'); const os = require('node:os');
    const out = {};
    out.uid = process.getuid(); out.gid = process.getgid();
    out.env = Object.keys(process.env).sort();
    try { fs.writeFileSync('/etc/pwned', 'x'); out.rootWrite = 'allowed'; } catch (e) { out.rootWrite = e.code; }
    try { fs.writeFileSync('/work/src/probe.txt', 'x'); out.workWrite = 'ok'; } catch (e) { out.workWrite = e.code; }
    out.ifaces = Object.keys(os.networkInterfaces());
    out.dockerSock = fs.existsSync('/var/run/docker.sock');
    const tryConnect = (host, port) => new Promise((r) => {
      const s = net.connect({ host, port, timeout: 2000 });
      s.on('connect', () => { s.destroy(); r('connected'); });
      s.on('error', (e) => r(e.code)); s.on('timeout', () => { s.destroy(); r('timeout'); });
    });
    Promise.all([tryConnect('1.1.1.1', 443), tryConnect('169.254.169.254', 80), tryConnect('172.17.0.1', 2375)]).then((n) => {
      out.net = n; console.log('PRO' + 'BE ' + JSON.stringify(out));
    });`;
  const { res, text } = await exec(createRunner(cfg()), 'node', [probe(['node', '-e', script])], nodeSource);
  assert.equal(res.outcome, 'succeeded', text);
  const data = JSON.parse(/^PROBE (.*)$/m.exec(text)?.[1] ?? '{}');
  assert.equal(data.uid, 65532);
  assert.equal(data.gid, 65532);
  assert.equal(data.rootWrite, 'EROFS');
  assert.equal(data.workWrite, 'ok');
  assert.deepEqual(data.ifaces, ['lo'], 'only loopback');
  assert.equal(data.dockerSock, false);
  for (const r of data.net) assert.notEqual(r, 'connected');
  for (const k of data.env) assert.ok(['HOME', 'TMPDIR', 'PATH', 'HOSTNAME', 'CGO_ENABLED'].includes(k), `unexpected env ${k}`);
});

test('timeout kills the whole process tree and removes the sandbox', { skip }, async () => {
  const marker = `rr-marker-${Date.now()}`;
  const script = `
    const { spawn } = require('node:child_process');
    for (let i = 0; i < 5; i++) spawn('sleep', ['1000', '${marker}'], { detached: true, stdio: 'ignore' }).unref();
    console.log('spawned'); setInterval(() => {}, 1000);`;
  const runner = createRunner(cfg({ REPORADAR_CHECK_TIMEOUT_SEC: '10' }));
  const start = Date.now();
  const { res, text } = await exec(runner, 'node', [probe(['node', '-e', script])], nodeSource);
  assert.equal(res.outcome, 'timed_out', text);
  assert.ok(Date.now() - start < 30_000);
  assert.match(text, /spawned/);
  assert.equal(res.cleanup, 'confirmed');
  await new Promise((r) => setTimeout(r, 500));
  let stray = '';
  try {
    stray = execFileSync('pgrep', ['-f', marker]).toString();
  } catch {
    stray = '';
  }
  assert.equal(stray.trim(), '', 'no sandboxed process survives');
  assert.equal(leftovers(), '');
});

test('cancellation stops a running sandbox', { skip }, async () => {
  const ac = new AbortController();
  const p = exec(createRunner(cfg()), 'node', [probe(['node', '-e', 'console.log("busy"); setInterval(() => {}, 1000)'])], nodeSource, { signal: ac.signal });
  setTimeout(() => ac.abort(), 2500);
  const { res } = await p;
  assert.equal(res.outcome, 'cancelled');
  assert.equal(res.cleanup, 'confirmed');
  assert.equal(leftovers(), '');
});

test('memory, process and workspace limits are enforced outside the process', { skip }, async () => {
  const runner = createRunner(cfg({ REPORADAR_RUN_MEMORY_MB: '256', REPORADAR_RUN_PIDS: '64', REPORADAR_RUN_WORKSPACE_MB: '64' }));
  const mem = await exec(runner, 'node', [probe(['node', '-e', 'const a = []; for (;;) a.push(Buffer.alloc(16 * 1024 * 1024, 1));'])], nodeSource);
  assert.equal(mem.res.outcome, 'failed');
  assert.ok(mem.res.exitCode === 137 || mem.res.exitCode === 134, `exit ${mem.res.exitCode}`);

  const pids = await exec(
    runner,
    'node',
    [probe(['node', '-e', `const { spawn } = require('node:child_process'); let ok = 0, err = 0;
      for (let i = 0; i < 200; i++) { try { const c = spawn('sleep', ['30']); c.on('error', () => err++); ok++; } catch { err++; } }
      setTimeout(() => { console.log('PI' + 'DS', ok, err); process.exit(0); }, 1500);`])],
    nodeSource,
  );
  const pidLine = /^PIDS (\d+) (\d+)$/m.exec(pids.text);
  assert.ok(pidLine && Number(pidLine[2]) > 0, `expected spawn failures under the PID limit: ${pids.text.slice(-400)}`);

  const disk = await exec(runner, 'node', [probe(['node', '-e', `const fs = require('node:fs'); const b = Buffer.alloc(1 << 20);
      try { for (let i = 0; i < 200; i++) fs.appendFileSync('/work/big.bin', b); console.log('WROTE ALL'); } catch (e) { console.log('DI' + 'SK', e.code); }`])], nodeSource);
  assert.match(disk.text, /^DISK ENOSPC$/m);
  assert.equal(leftovers(), '');
});

test('huge output is capped while streaming and the run still completes', { skip }, async () => {
  const log = new RunLog({ headBytes: 64 * 1024, tailBytes: 16 * 1024 });
  const { res, text } = await exec(
    createRunner(cfg()),
    'node',
    [probe(['node', '-e', `const l = 'x'.repeat(1000) + '\\n'; for (let i = 0; i < 50000; i++) process.stdout.write(l); console.log('THE END');`])],
    nodeSource,
    { log },
  );
  assert.equal(res.outcome, 'succeeded');
  assert.ok(log.receivedBytes > 49_000_000);
  assert.ok(Buffer.byteLength(text) < 100 * 1024);
  assert.match(text, /omitted/);
  assert.match(text, /THE END/);
});

test('fails closed when the configured runtime is missing', { skip }, async () => {
  const status = await createRunner(cfg({ REPORADAR_DOCKER_RUNTIME: 'runsc' })).status(true);
  const hasRunsc = execFileSync('docker', ['info', '--format', '{{json .Runtimes}}']).toString().includes('"runsc"');
  if (!hasRunsc) {
    assert.equal(status.available, false);
    assert.match(status.reason ?? '', /gVisor/);
  } else {
    assert.equal(status.available, true);
  }
});
