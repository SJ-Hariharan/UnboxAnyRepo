import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DockerRunner, buildRunArgs } from '../../src/runner/docker.ts';
import { createRunner, DisabledRunner } from '../../src/runner/factory.ts';
import type { ExecuteRequest } from '../../src/runner/types.ts';
import type { StepPlan } from '../../src/checks/types.ts';
import { UNSAFE_LOCAL_ACK } from '../../src/config.ts';
import { FakeDocker, gunzipTar } from '../helpers/fake-docker.ts';
import { testConfig, testLimits } from '../helpers/limits.ts';
import { gz, buildTar } from '../helpers/tarbuilder.ts';

const IMAGES = ['node:24-bookworm-slim', 'python:3.13-slim-bookworm', 'golang:1.25-bookworm', 'rust:1-slim-bookworm'];

function runner(fake: FakeDocker, env: Record<string, string> = {}, limits = {}) {
  const cfg = testConfig({ UNBOX_RUNNER: 'docker', ...env });
  return new DockerRunner({ config: cfg.runner, limits: testLimits(limits), isolation: 'strong', exec: fake, statusTtlMs: 0, verification: { required: false } });
}

const CHECK: StepPlan = { kind: 'check', title: 'npm test', argv: ['npm', 'test'], env: { HOME: '/work/.home' }, network: 'none' };
const INSTALL: StepPlan = { kind: 'install', title: 'npm ci', argv: ['npm', 'ci', '--ignore-scripts'], env: {}, network: 'registry-proxy' };

function request(steps: StepPlan[], signal = new AbortController().signal) {
  const log: string[] = [];
  const phases: string[] = [];
  const req: ExecuteRequest = {
    ecosystem: 'node',
    steps,
    source: gz(buildTar([{ name: 'src/', type: '5' }, { name: 'src/a.js', data: 'x' }])),
    signal,
    onPhase: (p) => phases.push(p),
    onOutput: (_s, c) => log.push(c.toString()),
    onOutputEnd: () => {},
    onSystem: (t) => log.push(`# ${t}`),
  };
  return { req, log, phases };
}

test('docker run arguments always carry the hardening flags', () => {
  const args = buildRunArgs({
    name: 'unbox-0123456789abcdef-s0',
    tag: '0123456789abcdef',
    runtime: 'runsc',
    image: 'node:24',
    network: 'none',
    volume: 'unbox-0123456789abcdef',
    argv: ['npm', 'test'],
    env: { HOME: '/work/.home' },
    workdir: '/work/src',
    limits: { runCpus: 1, runMemoryMiB: 512, runPids: 128 },
  });
  const joined = args.join(' ');
  for (const expected of [
    '--rm', '--runtime runsc', '--pull never', '--network none', '--user 65532:65532', '--cap-drop ALL',
    '--security-opt no-new-privileges=true', '--read-only', '--memory 512m', '--memory-swap 512m', '--cpus 1',
    '--pids-limit 128', '--entrypoint npm', '--env HOME=/work/.home', '--log-driver none',
  ]) {
    assert.ok(joined.includes(expected), expected);
  }
  assert.ok(!joined.includes('--privileged'));
  assert.ok(!joined.includes('docker.sock'));
  assert.ok(!/(^| )-v /.test(joined), 'no bind mounts');
  assert.deepEqual(args.slice(-2), ['node:24', 'test']);
  const base = { name: 'n', tag: 't', runtime: 'runsc', image: 'i', network: 'none', volume: 'v', workdir: '/w', limits: { runCpus: 1, runMemoryMiB: 512, runPids: 64 } };
  assert.throws(() => buildRunArgs({ ...base, argv: ['--privileged'], env: {} }));
  assert.throws(() => buildRunArgs({ ...base, argv: ['npm'], env: { 'BAD KEY': 'x' } }));
  assert.throws(() => buildRunArgs({ ...base, argv: ['npm'], env: { OK: 'a\nb' } }));
});

test('factory fails closed', async () => {
  assert.ok(createRunner(testConfig()) instanceof DisabledRunner);
  assert.ok(createRunner(testConfig({ UNBOX_RUNNER: 'docker', UNBOX_DOCKER_RUNTIME: 'runc' })) instanceof DisabledRunner);
  const prod = createRunner(
    testConfig({ NODE_ENV: 'production', UNBOX_RUNNER: 'docker', UNBOX_DOCKER_RUNTIME: 'runc', UNBOX_ALLOW_UNSAFE_LOCAL_RUNNER: UNSAFE_LOCAL_ACK }),
  );
  assert.ok(prod instanceof DisabledRunner);
  const unsafe = createRunner(
    testConfig({ UNBOX_RUNNER: 'docker', UNBOX_DOCKER_RUNTIME: 'runc', UNBOX_ALLOW_UNSAFE_LOCAL_RUNNER: UNSAFE_LOCAL_ACK }),
    new FakeDocker({ images: IMAGES }),
  );
  assert.equal((await unsafe.status()).isolation, 'unsafe-local');
  const strong = createRunner(testConfig({ UNBOX_RUNNER: 'docker' }), new FakeDocker({ images: IMAGES }));
  const st = await strong.status();
  assert.equal(st.isolation, 'strong');
  assert.equal(st.available, false, 'gVisor alone is not enough: the sandbox must have been verified');
  assert.match(st.reason ?? '', /npm run sandbox -- --verify/);
  const disabled = await new DisabledRunner('off').execute();
  assert.equal(disabled.outcome, 'unavailable');
});

test('status: unavailable without gVisor, unreachable host, or images; fetch needs an internal network', async () => {
  let s = await runner(new FakeDocker({ runtimes: ['runc'], images: IMAGES })).status();
  assert.equal(s.available, false);
  assert.match(s.reason ?? '', /gVisor/);
  s = await runner(new FakeDocker({ unreachable: true })).status();
  assert.equal(s.available, false);
  s = await runner(new FakeDocker({ images: [] })).status();
  assert.equal(s.available, false);
  s = await runner(new FakeDocker({ images: ['node:24-bookworm-slim'] })).status();
  assert.equal(s.available, true);
  assert.equal(s.ecosystems.node.available, true);
  assert.equal(s.ecosystems.rust.available, false);
  assert.equal(s.dependencyFetch, false);
  const fetchEnv = { UNBOX_FETCH_NETWORK: 'unbox-fetch', UNBOX_FETCH_PROXY_URL: 'http://unbox-egress:3128' };
  s = await runner(new FakeDocker({ images: IMAGES, networks: { 'unbox-fetch': { internal: false } } }), fetchEnv).status();
  assert.equal(s.dependencyFetch, false);
  assert.match(s.dependencyFetchReason ?? '', /not an internal network/);
  s = await runner(new FakeDocker({ images: IMAGES, networks: { 'unbox-fetch': { internal: true } } }), fetchEnv).status();
  assert.equal(s.dependencyFetch, true);
});

test('successful run: tmpfs workspace, source via stdin, no network, full cleanup', async () => {
  const fake = new FakeDocker({ images: IMAGES, steps: { 'npm test': { stdout: ['ok 1\n'], exitCode: 0 } } });
  const { req, log, phases } = request([CHECK]);
  const res = await runner(fake).execute(req);
  assert.equal(res.outcome, 'succeeded');
  assert.equal(res.cleanup, 'confirmed');
  assert.deepEqual(phases, ['preparing', 'running']);
  assert.ok(log.includes('ok 1\n'));
  const volCreate = fake.calls.find((c) => c[0] === 'volume' && c[1] === 'create');
  assert.ok(volCreate?.join(' ').includes('type=tmpfs'));
  assert.ok(volCreate?.join(' ').includes('uid=65532'));
  assert.ok(gunzipTar(req.source).equals(fake.stdinReceived as Buffer), 'source streamed into the sandbox');
  const step = fake.stepRuns()[0] as string[];
  assert.equal(step[step.indexOf('--network') + 1], 'none');
  assert.equal(fake.containers.size, 0);
  assert.equal(fake.volumes.size, 0);
  assert.deepEqual([...fake.bins], ['docker'], 'only the docker CLI is ever executed on the host');
});

test('failed check reports the exit code and the failing step', async () => {
  const fake = new FakeDocker({ images: IMAGES, steps: { 'npm test': { stdout: ['not ok\n'], exitCode: 1 } } });
  const res = await runner(fake).execute(request([CHECK]).req);
  assert.equal(res.outcome, 'failed');
  assert.equal(res.exitCode, 1);
  assert.equal(res.failedStep, 'check');
  assert.equal(fake.containers.size, 0);
});

test('timeout force-removes the container (killing its process tree) and cleans up', async () => {
  const fake = new FakeDocker({ images: IMAGES, steps: { 'npm test': { hang: true } } });
  const start = Date.now();
  const res = await runner(fake, {}, { checkTimeoutSec: 1 }).execute(request([CHECK]).req);
  assert.equal(res.outcome, 'timed_out');
  assert.ok(Date.now() - start < 5000);
  assert.ok(fake.calls.some((c) => c[0] === 'rm' && c[1] === '-f' && /-s0$/.test(c[2] ?? '')), 'step container force-removed');
  assert.equal(res.cleanup, 'confirmed');
  assert.equal(fake.containers.size, 0);
  assert.equal(fake.volumes.size, 0);
});

test('cancellation stops the sandbox and reports cancelled', async () => {
  const fake = new FakeDocker({ images: IMAGES, steps: { 'npm test': { hang: true } } });
  const ac = new AbortController();
  const { req } = request([CHECK], ac.signal);
  const p = runner(fake).execute(req);
  setTimeout(() => ac.abort(), 50);
  const res = await p;
  assert.equal(res.outcome, 'cancelled');
  assert.equal(res.cleanup, 'confirmed');
  assert.equal(fake.containers.size, 0);
});

test('install steps use the internal registry network and proxy; refused when not configured', async () => {
  const fetchEnv = { UNBOX_FETCH_NETWORK: 'unbox-fetch', UNBOX_FETCH_PROXY_URL: 'http://unbox-egress:3128' };
  const fake = new FakeDocker({ images: IMAGES, networks: { 'unbox-fetch': { internal: true } } });
  const res = await runner(fake, fetchEnv).execute(request([INSTALL, CHECK]).req);
  assert.equal(res.outcome, 'succeeded');
  const [install, check] = fake.stepRuns();
  assert.equal(install?.[install.indexOf('--network') + 1], 'unbox-fetch');
  assert.ok(install?.includes('HTTPS_PROXY=http://unbox-egress:3128'));
  assert.equal(check?.[check.indexOf('--network') + 1], 'none');
  assert.ok(!check?.some((a) => a.startsWith('HTTPS_PROXY')));

  const noFetch = new FakeDocker({ images: IMAGES });
  const res2 = await runner(noFetch).execute(request([INSTALL, CHECK]).req);
  assert.equal(res2.outcome, 'unavailable');
  assert.equal(noFetch.stepRuns().length, 0, 'nothing executed');
});

test('docker CLI errors are not forwarded to users', async () => {
  const fake = new FakeDocker({
    images: IMAGES,
    steps: { 'npm test': { stderr: ['docker: Error response from daemon: /var/lib/docker/secret-path failed\n'], exitCode: 125 } },
  });
  const { req, log } = request([CHECK]);
  const res = await runner(fake).execute(req);
  assert.equal(res.outcome, 'unavailable');
  assert.ok(!log.join('').includes('/var/lib/docker'));
});

test('workspace creation failure is reported as unavailable, not as a result', async () => {
  const res = await runner(new FakeDocker({ images: IMAGES, failVolumeCreate: true })).execute(request([CHECK]).req);
  assert.equal(res.outcome, 'unavailable');
});

test('sweep removes stale sandboxes but never ones in flight', async () => {
  const stale = 'aaaaaaaaaaaaaaaa';
  const fake = new FakeDocker({
    images: IMAGES,
    steps: { 'npm test': { hang: true } },
    containers: [{ name: `unbox-${stale}-s0`, tag: stale }, { name: 'unrelated', tag: '' }],
    volumes: [`unbox-${stale}`, 'someone-elses-volume'],
  });
  const r = runner(fake, {}, { checkTimeoutSec: 2 });
  const ac = new AbortController();
  const running = r.execute(request([CHECK], ac.signal).req);
  await new Promise((res) => setTimeout(res, 100));
  await r.sweep();
  assert.ok(!fake.containers.has(`unbox-${stale}-s0`));
  assert.ok(!fake.volumes.has(`unbox-${stale}`));
  assert.ok(fake.containers.has('unrelated'));
  assert.ok(fake.volumes.has('someone-elses-volume'));
  assert.ok([...fake.containers.keys()].some((n) => n.endsWith('-s0') && !n.includes(stale)), 'active run untouched');
  ac.abort();
  assert.equal((await running).outcome, 'cancelled');
});
