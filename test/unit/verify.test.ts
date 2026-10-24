import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DockerRunner } from '../../src/runner/docker.ts';
import { parseAttestation, checkAttestation, ATTESTATION_SCHEMA } from '../../src/runner/verify.ts';
import type { Attestation } from '../../src/runner/verify.ts';
import type { ExecuteRequest } from '../../src/runner/types.ts';
import { FakeDocker } from '../helpers/fake-docker.ts';
import { testConfig, testLimits } from '../helpers/limits.ts';
import { gz, buildTar } from '../helpers/tarbuilder.ts';

const NODE = 'node:24-bookworm-slim';
const ID = `sha256:${'a'.repeat(64)}`;

function att(over: Partial<Attestation> = {}): Attestation {
  return {
    schema: ATTESTATION_SCHEMA,
    createdAt: new Date().toISOString(),
    runtime: 'runsc',
    dockerHost: null,
    dockerServerVersion: '27.0.0',
    gvisorProbe: 'Starting gVisor...',
    images: { node: { ref: NODE, id: ID } },
    tests: [{ name: 'sandbox properties', status: 'PASS' }],
    allRequiredPassed: true,
    ...over,
  };
}

function strong(fake: FakeDocker, attestation: Attestation | undefined, env: Record<string, string> = {}) {
  const cfg = testConfig({ UNBOX_RUNNER: 'docker', ...env });
  return new DockerRunner({
    config: cfg.runner, limits: testLimits(), isolation: 'strong', exec: fake, statusTtlMs: 0,
    verification: { required: true, file: '/nonexistent', maxAgeDays: 30 },
    loadAttestation: () => attestation,
  });
}

test('a runtime named runsc that is not gVisor is refused', async () => {
  const s = await strong(new FakeDocker({ images: [NODE], imageIds: { [NODE]: ID }, kernel: 'linux' }), att()).status();
  assert.equal(s.available, false);
  assert.match(s.reason ?? '', /did not identify itself as gVisor/);
  assert.equal(s.verification?.gvisorProbe, 'failed');
});

test('gVisor without a verification record is refused; a valid record enables only verified images', async () => {
  const fake = () => new FakeDocker({ images: [NODE, 'python:3.13-slim-bookworm'], imageIds: { [NODE]: ID, 'python:3.13-slim-bookworm': `sha256:${'b'.repeat(64)}` } });
  let s = await strong(fake(), undefined).status();
  assert.equal(s.available, false);
  assert.match(s.reason ?? '', /has not been verified/);
  s = await strong(fake(), att()).status();
  assert.equal(s.available, true);
  assert.equal(s.ecosystems.node.available, true);
  assert.equal(s.ecosystems.python.available, false, 'python image was not part of the verification');
  assert.match(s.ecosystems.python.reason ?? '', /changed since the sandbox was verified/);
  assert.equal(s.verification?.recorded, 'valid');
});

test('stale records, other Docker hosts and changed images invalidate verification', async () => {
  const fake = () => new FakeDocker({ images: [NODE], imageIds: { [NODE]: ID } });
  const old = att({ createdAt: new Date(Date.now() - 40 * 86_400_000).toISOString() });
  assert.match((await strong(fake(), old).status()).reason ?? '', /older than 30 days/);
  assert.match((await strong(fake(), att({ dockerHost: 'ssh://other' })).status()).reason ?? '', /different Docker host/);
  const changed = new FakeDocker({ images: [NODE], imageIds: { [NODE]: `sha256:${'c'.repeat(64)}` } });
  assert.match((await strong(changed, att()).status()).reason ?? '', /No sandbox image matches/);
});

test('records are only accepted when every listed test passed', () => {
  assert.ok(parseAttestation(att()));
  assert.equal(parseAttestation({ ...att(), tests: [{ name: 'x', status: 'FAIL' }] }), undefined);
  assert.equal(parseAttestation({ ...att(), tests: [{ name: 'x', status: 'NOT RUN' }] }), undefined);
  assert.equal(parseAttestation({ ...att(), allRequiredPassed: false }), undefined);
  assert.equal(parseAttestation({ ...att(), runtime: 'runc' }), undefined);
  assert.equal(parseAttestation({ ...att(), tests: [] }), undefined);
  assert.equal(parseAttestation(null), undefined);
  assert.deepEqual(checkAttestation(att(), { dockerHost: null, imageIds: { node: ID } }, 30).ok, ['node']);
});

test('build output is collected from the sandbox only after success, bounded in size', async () => {
  const tar = buildTar([{ name: './index.html', data: '<html>' }]);
  const mk = (artifact?: Buffer) => new DockerRunner({ config: testConfig({ UNBOX_RUNNER: 'docker' }).runner, limits: testLimits(), isolation: 'strong', exec: new FakeDocker({ images: [NODE], artifact }), statusTtlMs: 0, verification: { required: false } });
  const req = (collect?: ExecuteRequest['collect']): ExecuteRequest => ({
    ecosystem: 'node',
    steps: [{ kind: 'check', title: 'build', argv: ['npm', 'run', 'build'], env: {}, network: 'none' }],
    source: gz(buildTar([{ name: 'src/', type: '5' }])),
    signal: new AbortController().signal,
    onPhase() {}, onOutput() {}, onOutputEnd() {}, onSystem() {},
    ...(collect ? { collect } : {}),
  });
  const ok = await mk(tar).execute(req({ dir: 'dist', maxBytes: 1e6 }));
  assert.equal(ok.outcome, 'succeeded');
  assert.ok(ok.artifact?.equals(tar));
  assert.equal(ok.cleanup, 'confirmed');
  const big = await mk(tar).execute(req({ dir: 'dist', maxBytes: 100 }));
  assert.equal(big.artifact, undefined);
  assert.match(big.artifactError ?? '', /larger than/);
  const missing = await mk(undefined).execute(req({ dir: 'dist', maxBytes: 1e6 }));
  assert.match(missing.artifactError ?? '', /did not produce dist/);
  const bad = await mk(tar).execute(req({ dir: '../etc', maxBytes: 1e6 }));
  assert.match(bad.artifactError ?? '', /not a plain relative path/);
});
