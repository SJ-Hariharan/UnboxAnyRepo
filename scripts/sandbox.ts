/**
 * Sandbox diagnostics for operators.
 *
 *   npm run sandbox                 report what is installed and configured (runs only harmless probes)
 *   npm run sandbox -- --verify     also run the real-container tests; on success, record the result
 *   npm run sandbox -- --json       machine-readable output
 *
 * Every line has one status:
 *   PASS     checked and correct
 *   FAIL     checked and wrong
 *   BLOCKED  could not be checked because something it depends on is missing
 *   NOT RUN  deliberately not checked (for example, tests without --verify)
 *   UNKNOWN  checked, but the answer cannot be established from here
 *
 * The real-container tests are never run with the runc runtime: their purpose
 * is to verify a strong sandbox, and running them under runc would execute the
 * probes with only ordinary container isolation.
 */
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { run } from 'node:test';
import { loadConfig, ConfigError } from '../src/config.ts';
import type { Ecosystem } from '../src/config.ts';
import { ProcessExecutor, minimalEnv } from '../src/runner/exec.ts';
import { createRunner } from '../src/runner/factory.ts';
import { gvisorProbeArgs } from '../src/runner/docker.ts';
import { loadAttestation, checkAttestation, isGvisorKernelLog, ATTESTATION_SCHEMA } from '../src/runner/verify.ts';
import type { Attestation, CheckStatus } from '../src/runner/verify.ts';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = new Set(process.argv.slice(2));
const verify = args.has('--verify');
const asJson = args.has('--json');

interface Line {
  section: string;
  name: string;
  status: CheckStatus | 'INFO';
  detail: string;
}
const lines: Line[] = [];
const add = (section: string, name: string, status: Line['status'], detail: string) => lines.push({ section, name, status, detail });

let config;
try {
  config = loadConfig({ ...process.env, UNBOX_RUNNER: 'docker' });
} catch (err) {
  console.error(`Configuration error: ${err instanceof ConfigError ? err.message : String(err)}`);
  process.exit(2);
}
const r = config.runner;
const exec = new ProcessExecutor(minimalEnv(r.dockerHost ? { DOCKER_HOST: r.dockerHost } : {}));
const docker = (a: string[], ms = 30_000) => exec.run(r.dockerBin, a, ms);

add('host', 'Operating system', 'INFO', `${os.type()} ${os.release()} (${os.platform()}/${os.arch()})`);
add('host', 'Node.js', 'INFO', process.version);
add('config', 'Execution setting', 'INFO', `UNBOX_RUNNER=${process.env.UNBOX_RUNNER ?? 'disabled'} (this command checks the Docker setup regardless)`);
add('config', 'Runtime', r.runtime === 'runsc' ? 'INFO' : 'FAIL', r.runtime === 'runsc' ? 'runsc (gVisor)' : 'runc: not a strong sandbox; it can never be verified');
add('config', 'Docker host', 'INFO', r.dockerHost ?? 'local daemon');

const ver = await docker(['version', '--format', '{{.Client.Version}}'], 15_000);
const cliOk = ver.code !== 127 && ver.stdout.trim() !== '';
add('docker', 'Docker CLI', cliOk ? 'PASS' : 'FAIL', cliOk ? `client ${ver.stdout.trim()}` : `"${r.dockerBin}" was not found or did not run`);
const info = cliOk ? await docker(['info', '--format', '{{json .}}'], 20_000) : undefined;
let serverVersion = '';
let runtimes: string[] = [];
if (!info || info.code !== 0) {
  add('docker', 'Docker daemon', cliOk ? 'FAIL' : 'BLOCKED', cliOk ? 'not reachable (is Docker running? is DOCKER_HOST correct?)' : 'needs the Docker CLI');
} else {
  try {
    const j = JSON.parse(info.stdout) as { ServerVersion?: string; OSType?: string; Architecture?: string; OperatingSystem?: string; Runtimes?: Record<string, unknown>; CgroupVersion?: string };
    serverVersion = j.ServerVersion ?? '';
    runtimes = Object.keys(j.Runtimes ?? {});
    add('docker', 'Docker daemon', 'PASS', `server ${serverVersion} on ${j.OperatingSystem ?? j.OSType} (${j.Architecture}), cgroup v${j.CgroupVersion ?? '?'}`);
  } catch {
    add('docker', 'Docker daemon', 'UNKNOWN', 'unexpected response from docker info');
  }
}
const daemonOk = serverVersion !== '';
const hasRunsc = runtimes.includes('runsc');
add('runtime', 'Registered runtimes', daemonOk ? 'INFO' : 'BLOCKED', daemonOk ? runtimes.join(', ') || 'none' : 'needs the Docker daemon');
add('runtime', 'gVisor (runsc) registered', !daemonOk ? 'BLOCKED' : hasRunsc ? 'PASS' : 'FAIL', !daemonOk ? 'needs the Docker daemon' : hasRunsc ? 'runsc is registered with Docker' : 'install gVisor and run "sudo runsc install" on the sandbox host (gVisor runs on Linux; Docker Desktop on macOS does not provide it)');

const imageIds: Partial<Record<Ecosystem, string>> = {};
for (const eco of ['node', 'python', 'go', 'rust'] as Ecosystem[]) {
  const ref = r.images[eco];
  if (!daemonOk) {
    add('images', `${eco} image`, 'BLOCKED', `${ref}: needs the Docker daemon`);
    continue;
  }
  const insp = await docker(['image', 'inspect', '--format', '{{.Id}} {{json .RepoDigests}}', ref]);
  if (insp.code !== 0) {
    add('images', `${eco} image`, 'FAIL', `${ref} is not pulled (run: node scripts/pull-images.ts)`);
    continue;
  }
  const [id, digestsJson] = insp.stdout.trim().split(' ', 2) as [string, string | undefined];
  imageIds[eco] = id;
  const pinned = /@sha256:([a-f0-9]{64})$/.exec(ref)?.[1];
  let digests: string[] = [];
  try {
    digests = JSON.parse(digestsJson ?? '[]') as string[];
  } catch {
    digests = [];
  }
  if (!pinned) add('images', `${eco} image`, 'UNKNOWN', `${ref} present (${id.slice(0, 19)}), but not pinned by digest, so its integrity cannot be checked`);
  else add('images', `${eco} image`, digests.some((d) => d.endsWith(`@sha256:${pinned}`)) ? 'PASS' : 'FAIL', digests.some((d) => d.endsWith(`@sha256:${pinned}`)) ? `${ref} matches its pinned digest` : `${ref}: local image does not carry the pinned digest`);
}

let probeOutput = '';
const probeImage = (['node', 'python', 'go', 'rust'] as Ecosystem[]).map((e) => (imageIds[e] ? r.images[e] : undefined)).find(Boolean);
if (!hasRunsc || r.runtime !== 'runsc') add('runtime', 'gVisor probe', 'BLOCKED', 'needs runsc registered and UNBOX_DOCKER_RUNTIME=runsc');
else if (!probeImage) add('runtime', 'gVisor probe', 'BLOCKED', 'needs at least one sandbox image');
else {
  const p = await docker(gvisorProbeArgs('runsc', probeImage), 90_000);
  probeOutput = p.stdout.split('\n').find((l) => /gVisor/.test(l))?.trim() ?? '';
  add('runtime', 'gVisor probe', p.code === 0 && isGvisorKernelLog(p.stdout) ? 'PASS' : 'FAIL', p.code === 0 && isGvisorKernelLog(p.stdout) ? `kernel log in a test container: "${probeOutput.slice(0, 80)}"` : 'a runsc container did not report a gVisor kernel');
}

if (!r.fetchNetwork) add('network', 'Dependency-fetch network', 'NOT RUN', 'not configured (checks that download dependencies stay disabled)');
else if (!daemonOk) add('network', 'Dependency-fetch network', 'BLOCKED', 'needs the Docker daemon');
else {
  const n = await docker(['network', 'inspect', '--format', '{{.Internal}} {{len .Containers}}', r.fetchNetwork]);
  const [internal, count] = n.stdout.trim().split(' ');
  add('network', 'Dependency-fetch network', n.code !== 0 ? 'FAIL' : internal === 'true' ? 'PASS' : 'FAIL', n.code !== 0 ? `${r.fetchNetwork} does not exist` : internal === 'true' ? `${r.fetchNetwork} is internal (no route out)` : `${r.fetchNetwork} is NOT internal`);
  add('network', 'Egress proxy attached', n.code !== 0 ? 'BLOCKED' : Number(count) > 0 ? 'UNKNOWN' : 'FAIL', n.code !== 0 ? 'needs the network' : Number(count) > 0 ? `${count} container(s) attached; allowlist behaviour is checked by the optional real-container test` : 'nothing is attached to the network');
}
add('network', 'Host firewall / cloud metadata egress', 'UNKNOWN', 'network-layer rules on the sandbox host cannot be inspected from here; see docs/DEPLOYMENT.md');

// ------------------------------------------------------------ integration tests
const required: { name: string; status: CheckStatus }[] = [];
let ranTests = false;
if (!verify) {
  add('tests', 'Real-container tests', 'NOT RUN', 'add --verify to run them');
} else if (r.runtime !== 'runsc') {
  add('tests', 'Real-container tests', 'BLOCKED', 'refusing to run under runc; configure runsc (gVisor)');
} else if (!lines.some((l) => l.name === 'gVisor probe' && l.status === 'PASS')) {
  add('tests', 'Real-container tests', 'BLOCKED', 'the gVisor probe must pass first');
} else {
  ranTests = true;
  process.env.UNBOX_TEST_DOCKER = '1';
  const stream = run({ files: [path.join(ROOT, 'test/integration/docker.test.ts')], concurrency: 1, timeout: 15 * 60_000 });
  await new Promise<void>((resolve) => {
    stream.on('test:pass', (d: { name: string; nesting: number; skip?: string | boolean; todo?: string | boolean }) => {
      if (d.nesting !== 0) return;
      const status: CheckStatus = d.skip ? (/BLOCKED/.test(String(d.skip)) ? 'BLOCKED' : 'NOT RUN') : 'PASS';
      add('tests', d.name, status, d.skip ? String(d.skip) : 'passed');
      if (!d.name.startsWith('[optional]')) required.push({ name: d.name, status });
    });
    stream.on('test:fail', (d: { name: string; nesting: number; details?: { error?: { message?: string } } }) => {
      if (d.nesting !== 0) return;
      add('tests', d.name, 'FAIL', (d.details?.error?.message ?? 'failed').split('\n')[0]?.slice(0, 200) ?? 'failed');
      if (!d.name.startsWith('[optional]')) required.push({ name: d.name, status: 'FAIL' });
    });
    stream.on('end', () => resolve());
    stream.on('data', () => {});
  });
}

// ------------------------------------------------------------- verification record
const file = path.resolve(config.sandboxVerification.file);
if (ranTests) {
  const allPassed = required.length > 0 && required.every((t) => t.status === 'PASS');
  if (allPassed) {
    const images: Attestation['images'] = {};
    for (const [eco, id] of Object.entries(imageIds) as [Ecosystem, string][]) images[eco] = { ref: r.images[eco], id };
    const att: Attestation = {
      schema: ATTESTATION_SCHEMA,
      createdAt: new Date().toISOString(),
      runtime: 'runsc',
      dockerHost: r.dockerHost ?? null,
      dockerServerVersion: serverVersion,
      gvisorProbe: probeOutput.slice(0, 200),
      images,
      tests: required,
      allRequiredPassed: true,
    };
    mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    writeFileSync(file, `${JSON.stringify(att, null, 2)}\n`, { mode: 0o600 });
    add('verification', 'Verification record', 'PASS', `all ${required.length} required tests passed; written to ${path.relative(process.cwd(), file)}`);
  } else {
    add('verification', 'Verification record', 'FAIL', 'not written: not every required test passed');
  }
} else {
  const att = loadAttestation(file);
  const check = checkAttestation(att, { dockerHost: r.dockerHost ?? null, imageIds }, config.sandboxVerification.maxAgeDays);
  add('verification', 'Verification record', att ? (check.ok.length ? 'PASS' : 'FAIL') : 'NOT RUN', att ? (check.ok.length ? `valid for ${check.ok.join(', ')} (recorded ${att.createdAt})` : (check.reason ?? 'invalid')) : 'none recorded yet');
}

// ------------------------------------------------------------------- worker
const runner = createRunner({ ...config, runner: { ...config.runner, mode: 'docker' } });
const status = await runner.status(true);
add('worker', 'Execution would be', status.available ? 'PASS' : 'FAIL', status.available ? `available: ${status.label}; ecosystems ${Object.entries(status.ecosystems).filter(([, e]) => e.available).map(([k]) => k).join(', ')}` : `disabled: ${status.reason ?? 'unavailable'}`);

if (asJson) {
  console.log(JSON.stringify({ generatedAt: new Date().toISOString(), lines }, null, 2));
} else {
  const width = Math.max(...lines.map((l) => l.name.length)) + 2;
  const order = ['host', 'config', 'docker', 'runtime', 'images', 'network', 'tests', 'verification', 'worker'];
  const sorted = lines.map((l, i) => ({ l, i })).sort((a, b) => order.indexOf(a.l.section) - order.indexOf(b.l.section) || a.i - b.i).map((x) => x.l);
  let section = '';
  for (const l of sorted) {
    if (l.section !== section) {
      section = l.section;
      console.log(`\n${section.toUpperCase()}`);
    }
    console.log(`  ${l.status.padEnd(8)} ${l.name.padEnd(width)} ${l.detail}`);
  }
  console.log('\nPASS = checked and correct · FAIL = checked and wrong · BLOCKED = a prerequisite is missing · NOT RUN = not checked · UNKNOWN = cannot be established here');
}
process.exitCode = lines.some((l) => l.status === 'FAIL') ? 1 : 0;
