import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RunManager, RunError } from '../../src/runs/manager.ts';
import type { RunView, RunEvent } from '../../src/runs/manager.ts';
import { InspectionStore } from '../../src/runs/inspections.ts';
import type { Inspection } from '../../src/runs/inspections.ts';
import { detectProject } from '../../src/detect/index.ts';
import { sanitizeArchive } from '../../src/source/archive.ts';
import { repoArchive } from '../helpers/tarbuilder.ts';
import { FakeRunner } from '../helpers/fake-runner.ts';
import { testLimits } from '../helpers/limits.ts';
import { fixtures } from '../fixtures/detection.ts';
import type { RepoFixture } from '../fixtures/detection.ts';

const LIM = { maxCompressedBytes: 1e7, maxUncompressedBytes: 1e7, maxFiles: 1000, maxFileBytes: 1e6 };

async function inspection(store: InspectionStore, sessionId: string, files: RepoFixture = fixtures.nodeNoDeps): Promise<Inspection> {
  const snap = await sanitizeArchive(repoArchive(files), LIM);
  return store.add({
    sessionId,
    repo: { owner: 'o', name: 'r', fullName: 'o/r', description: null, defaultBranch: 'main', language: null, htmlUrl: 'https://github.com/o/r', sizeKiB: 1, archived: false, fork: false },
    commitSha: 'a'.repeat(40),
    commitSource: 'default_branch',
    demo: false,
    notice: undefined,
    source: { fileCount: snap.files.length, totalBytes: snap.totalBytes, skippedSymlinkCount: 0, skippedSymlinks: [] },
    detection: detectProject(snap, { goImage: 'golang:1.25' }),
    sanitizedTarGz: snap.sanitizedTarGz,
  });
}

function waitFor(m: RunManager, id: string, session: string, pred: (v: RunView) => boolean, ms = 3000): Promise<RunView> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const tick = () => {
      const v = m.get(id, session);
      if (v && pred(v)) return resolve(v);
      if (Date.now() - start > ms) return reject(new Error(`timeout waiting; state=${v?.state}`));
      setTimeout(tick, 10);
    };
    tick();
  });
}

function setup(limits = {}, runner = new FakeRunner()) {
  const store = new InspectionStore({ ttlSec: 600 });
  const m = new RunManager({ runner, limits: testLimits(limits), secretValues: ['ghp_THISISASECRETTOKENVALUE1234567890ab'], watchdogMarginSec: 0 });
  return { store, m, runner };
}

const rejectsCode = (p: Promise<unknown>, code: string) =>
  assert.rejects(p, (e: unknown) => e instanceof RunError && e.code === code);

test('validates the requested check, acknowledgement and runner availability', async () => {
  const { store, m, runner } = setup();
  const insp = await inspection(store, 's1');
  await rejectsCode(m.create({ sessionId: 's1', inspection: insp, checkId: 'rm -rf /', acknowledged: true }), 'unknown_check');
  await rejectsCode(m.create({ sessionId: 's1', inspection: insp, checkId: 'go.test', acknowledged: true }), 'unknown_check');
  await rejectsCode(m.create({ sessionId: 's1', inspection: insp, checkId: 'node.npm-lint', acknowledged: true }), 'check_unavailable');
  await rejectsCode(m.create({ sessionId: 's1', inspection: insp, checkId: 'node.npm-test', acknowledged: 'yes' }), 'ack_required');
  runner.statusOverride = { available: false, reason: 'off' };
  await rejectsCode(m.create({ sessionId: 's1', inspection: insp, checkId: 'node.npm-test', acknowledged: true }), 'execution_unavailable');
  runner.statusOverride = { dependencyFetch: false };
  const withDeps = await inspection(store, 's1', fixtures.nodeBasic);
  await rejectsCode(m.create({ sessionId: 's1', inspection: withDeps, checkId: 'node.npm-test', acknowledged: true }), 'dependency_fetch_unavailable');
  assert.equal(runner.executions, 0);
});

test('runs to success, streams events, and records duration and cleanup', async () => {
  const { store, m } = setup();
  const insp = await inspection(store, 's1');
  const v = await m.create({ sessionId: 's1', inspection: insp, checkId: 'node.npm-test', acknowledged: true });
  assert.match(v.id, /^[a-f0-9]{32}$/);
  const events: RunEvent[] = [];
  m.subscribe(v.id, 's1', (e) => events.push(e));
  const done = await waitFor(m, v.id, 's1', (x) => x.terminal);
  assert.equal(done.state, 'succeeded');
  assert.equal(done.cleanup, 'confirmed');
  assert.ok(typeof done.durationMs === 'number');
  assert.ok(events.some((e) => e.type === 'state' && e.run.state === 'running'));
  assert.ok(m.logText(v.id, 's1')?.includes('ok'));
  assert.ok(done.nextSteps[0]?.includes('does not mean the code is safe'));
});

test('runs are invisible to other sessions', async () => {
  const { store, m } = setup();
  const insp = await inspection(store, 'owner');
  const v = await m.create({ sessionId: 'owner', inspection: insp, checkId: 'node.npm-test', acknowledged: true });
  assert.equal(m.get(v.id, 'intruder'), undefined);
  assert.equal(m.cancel(v.id, 'intruder'), undefined);
  assert.equal(m.subscribe(v.id, 'intruder', () => {}), undefined);
  assert.equal(m.logText(v.id, 'intruder'), undefined);
  assert.deepEqual(m.list('intruder'), []);
  assert.equal(store.get(insp.id, 'intruder'), undefined, 'inspections are session-bound too');
});

test('one active run per session; global queue limit', async () => {
  const runner = new FakeRunner();
  runner.script = { hang: true };
  const { store, m } = setup({ maxConcurrentRuns: 1, maxQueuedRuns: 1 }, runner);
  const a = await m.create({ sessionId: 'a', inspection: await inspection(store, 'a'), checkId: 'node.npm-test', acknowledged: true });
  await rejectsCode(m.create({ sessionId: 'a', inspection: await inspection(store, 'a'), checkId: 'node.npm-test', acknowledged: true }), 'session_busy');
  const b = await m.create({ sessionId: 'b', inspection: await inspection(store, 'b'), checkId: 'node.npm-test', acknowledged: true });
  assert.equal(b.state, 'queued');
  assert.equal(b.queuePosition, 1);
  await rejectsCode(m.create({ sessionId: 'c', inspection: await inspection(store, 'c'), checkId: 'node.npm-test', acknowledged: true }), 'queue_full');
  // Cancelling a queued run never executes anything.
  const cancelled = m.cancel(b.id, 'b');
  assert.equal(cancelled?.state, 'cancelled');
  assert.match(cancelled?.message ?? '', /No code was executed/);
  assert.equal(runner.executions, 1);
  m.cancel(a.id, 'a');
  const doneA = await waitFor(m, a.id, 'a', (x) => x.terminal);
  assert.equal(doneA.state, 'cancelled');
  assert.match(doneA.message ?? '', /every process in it were removed/);
  assert.throws(() => m.cancel(a.id, 'a'), (e: unknown) => e instanceof RunError && e.code === 'already_finished');
});

test('cancellation that the runner cannot confirm is reported honestly', async () => {
  const runner = new FakeRunner();
  runner.script = { hang: true };
  runner.execute = async (req) => {
    await new Promise<void>((r) => req.signal.addEventListener('abort', () => r(), { once: true }));
    return { outcome: 'cancelled', cleanup: 'unconfirmed' };
  };
  const { store, m } = setup({}, runner);
  const v = await m.create({ sessionId: 's', inspection: await inspection(store, 's'), checkId: 'node.npm-test', acknowledged: true });
  await new Promise((r) => setTimeout(r, 20));
  m.cancel(v.id, 's');
  const done = await waitFor(m, v.id, 's', (x) => x.terminal);
  assert.equal(done.state, 'cancelled');
  assert.match(done.message ?? '', /could not be confirmed/);
});

test('watchdog turns a runaway run into timed_out', async () => {
  const runner = new FakeRunner();
  runner.script = { hang: true };
  const { store, m } = setup({ installTimeoutSec: 0, checkTimeoutSec: 0 }, runner);
  const v = await m.create({ sessionId: 's', inspection: await inspection(store, 's'), checkId: 'node.npm-test', acknowledged: true });
  const done = await waitFor(m, v.id, 's', (x) => x.terminal);
  assert.equal(done.state, 'timed_out');
});

test('runner exceptions become "unavailable", never a fabricated result', async () => {
  const runner = new FakeRunner();
  runner.execute = async () => {
    throw new Error('/var/run/docker.sock exploded');
  };
  const { store, m } = setup({}, runner);
  const v = await m.create({ sessionId: 's', inspection: await inspection(store, 's'), checkId: 'node.npm-test', acknowledged: true });
  const done = await waitFor(m, v.id, 's', (x) => x.terminal);
  assert.equal(done.state, 'unavailable');
  assert.ok(!JSON.stringify(done).includes('docker.sock'));
});

test('logs are sanitized, redacted and capped through the manager', async () => {
  const runner = new FakeRunner();
  runner.script = {
    lines: [
      '\u001b[31mred\u001b[0m <script>alert(1)</script>\n',
      'token=ghp_THISISASECRETTOKENVALUE1234567890ab\n',
      ...Array.from({ length: 3000 }, (_, i) => `line ${i} ${'x'.repeat(60)}\n`),
      'FINAL LINE\n',
    ],
  };
  const { store, m } = setup({ logHeadBytes: 16 * 1024, logTailBytes: 4 * 1024 }, runner);
  const v = await m.create({ sessionId: 's', inspection: await inspection(store, 's'), checkId: 'node.npm-test', acknowledged: true });
  const done = await waitFor(m, v.id, 's', (x) => x.terminal);
  const text = m.logText(v.id, 's') ?? '';
  assert.ok(done.log.truncated);
  assert.ok(text.includes('red <script>alert(1)</script>'), 'kept as plain text');
  assert.ok(!text.includes('\u001b'));
  assert.ok(!text.includes('ghp_THISIS'));
  assert.match(text, /omitted; only the first/);
  assert.ok(text.includes('FINAL LINE'), 'tail retained');
  assert.ok(Buffer.byteLength(text) < 30 * 1024);
});

test('finished runs are purged after the retention period', async () => {
  const { store, m } = setup({ runRetentionSec: 0 });
  const v = await m.create({ sessionId: 's', inspection: await inspection(store, 's'), checkId: 'node.npm-test', acknowledged: true });
  await waitFor(m, v.id, 's', (x) => x.terminal);
  await new Promise((r) => setTimeout(r, 5));
  m.purge();
  assert.equal(m.get(v.id, 's'), undefined);
});
