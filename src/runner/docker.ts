/**
 * Docker sandbox runner.
 *
 * Supported production configuration: Docker with the gVisor runtime (runsc)
 * on a dedicated host or VM that holds no application secrets. Plain runc is
 * accepted only as an explicitly acknowledged, clearly labelled local
 * development mode (see runner/factory.ts).
 *
 * Per run:
 *   1. a tmpfs-backed volume (size-capped, owned by the sandbox uid) is created
 *      and held by a "keeper" container with no network;
 *   2. the sanitized source tar is streamed into it by a prepare container
 *      (no network);
 *   3. each planned step runs in a fresh container: --network none for checks,
 *      or the operator's internal registry-proxy network for installs;
 *   4. everything is force-removed afterwards (and on timeout/cancel), which
 *      kills every process in the sandbox, not just the entry process.
 *
 * Every container: non-root uid, all capabilities dropped, no-new-privileges,
 * read-only root filesystem, memory/CPU/PID/file-descriptor limits, no host
 * mounts, no Docker socket, no inherited environment, image entrypoint
 * overridden, images never pulled implicitly.
 */
import { randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import zlib from 'node:zlib';
import type { Ecosystem, RunnerConfig, Limits } from '../config.ts';
import type { StepPlan } from '../checks/types.ts';
import { SANDBOX_UID } from '../source/archive.ts';
import { WORK } from '../checks/templates.ts';
import type { CommandExecutor } from './exec.ts';
import type { ExecuteRequest, ExecuteResult, Runner, RunnerStatus, Isolation } from './types.ts';
import { loadAttestation, checkAttestation, isGvisorKernelLog } from './verify.ts';
import type { Attestation, VerificationOptions } from './verify.ts';

export const MANAGED_LABEL = 'unbox.managed=1';
const ECOSYSTEMS: Ecosystem[] = ['node', 'python', 'go', 'rust'];
const PREPARE_TIMEOUT_MS = 120_000;
const DOCKER_CMD_TIMEOUT_MS = 30_000;

export interface ContainerSpec {
  name: string;
  tag: string;
  runtime: string;
  image: string;
  network: string;
  volume: string;
  argv: readonly string[];
  env: Record<string, string>;
  workdir: string;
  limits: Pick<Limits, 'runCpus' | 'runMemoryMiB' | 'runPids'>;
  detach?: boolean;
  interactive?: boolean;
}

const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const SAFE_DIR_RE = /^[A-Za-z0-9._-]{1,60}(\/[A-Za-z0-9._-]{1,60}){0,5}$/;

/** Build the `docker run` argument vector. Pure; unit-tested. */
export function buildRunArgs(spec: ContainerSpec): string[] {
  const [entry, ...rest] = spec.argv;
  if (entry === undefined || entry.startsWith('-')) throw new Error('invalid command');
  const args = [
    'run',
    spec.detach ? '-d' : '--rm',
    ...(spec.interactive ? ['-i'] : []),
    '--name', spec.name,
    '--label', MANAGED_LABEL,
    '--label', `unbox.run=${spec.tag}`,
    '--runtime', spec.runtime,
    '--pull', 'never',
    '--network', spec.network,
    '--user', `${SANDBOX_UID}:${SANDBOX_UID}`,
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges=true',
    '--read-only',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m',
    '--memory', `${spec.limits.runMemoryMiB}m`,
    '--memory-swap', `${spec.limits.runMemoryMiB}m`,
    '--cpus', String(spec.limits.runCpus),
    '--pids-limit', String(spec.limits.runPids),
    '--ulimit', 'nofile=4096:4096',
    '--ulimit', 'core=0',
    '--ipc', 'private',
    '--hostname', 'sandbox',
    '--log-driver', 'none',
    '--mount', `type=volume,src=${spec.volume},dst=${WORK.root},volume-nocopy`,
    '--workdir', spec.workdir,
    '--entrypoint', entry,
  ];
  for (const [k, v] of Object.entries(spec.env)) {
    if (!ENV_KEY_RE.test(k) || v.includes('\n') || v.includes('\0')) throw new Error('invalid environment entry');
    args.push('--env', `${k}=${v}`);
  }
  args.push(spec.image, ...rest);
  return args;
}

export interface DockerRunnerOptions {
  config: RunnerConfig;
  limits: Limits;
  isolation: Isolation;
  exec: CommandExecutor;
  statusTtlMs?: number;
  /** Required for the strong runtime outside tests: see runner/verify.ts. */
  verification: VerificationOptions | { required: false };
  /** Test hook. */
  loadAttestation?: () => Attestation | undefined;
}

/** Constant, harmless probe: print the sandbox kernel log. gVisor identifies itself there. */
export function gvisorProbeArgs(runtime: string, image: string): string[] {
  return [
    'run', '--rm', '--runtime', runtime, '--pull', 'never', '--network', 'none',
    '--user', `${SANDBOX_UID}:${SANDBOX_UID}`, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true',
    '--read-only', '--memory', '256m', '--memory-swap', '256m', '--pids-limit', '64', '--log-driver', 'none',
    '--label', MANAGED_LABEL, '--entrypoint', 'dmesg', image,
  ];
}

export class DockerRunner implements Runner {
  readonly kind = 'docker';
  private readonly cfg: RunnerConfig;
  private readonly limits: Limits;
  private readonly isolation: Isolation;
  private readonly exec: CommandExecutor;
  private readonly statusTtlMs: number;
  private readonly verification: DockerRunnerOptions['verification'];
  private readonly loadAtt: () => Attestation | undefined;
  private cached: { at: number; status: RunnerStatus } | null = null;
  /** Tags of runs executing in this process; the sweeper never touches these. */
  private readonly active = new Set<string>();

  constructor(opts: DockerRunnerOptions) {
    this.cfg = opts.config;
    this.limits = opts.limits;
    this.isolation = opts.isolation;
    this.exec = opts.exec;
    this.statusTtlMs = opts.statusTtlMs ?? 30_000;
    this.verification = opts.verification;
    const v = opts.verification;
    this.loadAtt = opts.loadAttestation ?? (() => ('file' in v ? loadAttestation(v.file) : undefined));
  }

  private label(): string {
    return this.cfg.runtime === 'runsc' ? 'Docker + gVisor (runsc)' : 'Docker + runc (UNSAFE local development mode)';
  }

  private docker(args: readonly string[], timeoutMs = DOCKER_CMD_TIMEOUT_MS) {
    return this.exec.run(this.cfg.dockerBin, args, timeoutMs);
  }

  async status(force = false): Promise<RunnerStatus> {
    if (!force && this.cached && Date.now() - this.cached.at < this.statusTtlMs) return this.cached.status;
    const status = await this.computeStatus();
    this.cached = { at: Date.now(), status };
    return status;
  }

  private async computeStatus(): Promise<RunnerStatus> {
    const none = Object.fromEntries(ECOSYSTEMS.map((e) => [e, { available: false }])) as RunnerStatus['ecosystems'];
    const base: RunnerStatus = {
      available: false,
      isolation: this.isolation,
      label: this.label(),
      dependencyFetch: false,
      ecosystems: none,
      limits: {
        cpus: this.limits.runCpus,
        memoryMiB: this.limits.runMemoryMiB,
        pids: this.limits.runPids,
        workspaceMiB: this.limits.runWorkspaceMiB,
        installTimeoutSec: this.limits.installTimeoutSec,
        checkTimeoutSec: this.limits.checkTimeoutSec,
      },
    };
    const info = await this.docker(['info', '--format', '{{json .Runtimes}}']);
    if (info.code !== 0) return { ...base, reason: 'The sandbox host is not reachable right now.' };
    let runtimes: Record<string, unknown> = {};
    try {
      const parsed: unknown = JSON.parse(info.stdout.trim() || '{}');
      if (typeof parsed === 'object' && parsed !== null) runtimes = parsed as Record<string, unknown>;
    } catch {
      return { ...base, reason: 'The sandbox host returned an unexpected response.' };
    }
    if (!Object.hasOwn(runtimes, this.cfg.runtime)) {
      return {
        ...base,
        reason:
          this.cfg.runtime === 'runsc'
            ? 'The gVisor runtime (runsc) is not installed on the sandbox host, so execution is disabled.'
            : `The configured container runtime is not available on the sandbox host.`,
      };
    }

    const ecosystems = { ...none };
    const imageIds: Partial<Record<Ecosystem, string>> = {};
    for (const eco of ECOSYSTEMS) {
      const r = await this.docker(['image', 'inspect', '--format', '{{.Id}}', this.cfg.images[eco]]);
      ecosystems[eco] = r.code === 0 ? { available: true } : { available: false, reason: `The ${eco} sandbox image is not installed on the sandbox host.` };
      if (r.code === 0) imageIds[eco] = r.stdout.trim();
    }

    // Strong isolation must be demonstrated, not assumed from a runtime name.
    let verification: RunnerStatus['verification'] = { gvisorProbe: 'not_applicable', recorded: 'not_required' };
    if (this.cfg.runtime === 'runsc') {
      const probeImage = ECOSYSTEMS.map((e) => (ecosystems[e].available ? this.cfg.images[e] : undefined)).find(Boolean);
      if (!probeImage) return { ...base, reason: 'No sandbox images are installed on the sandbox host.' };
      const probe = await this.docker(gvisorProbeArgs('runsc', probeImage), 60_000);
      if (probe.code !== 0 || !isGvisorKernelLog(probe.stdout)) {
        return { ...base, reason: 'The runtime named "runsc" did not identify itself as gVisor in a test container, so execution is disabled.', verification: { gvisorProbe: 'failed', recorded: 'not_required' } };
      }
      verification = { gvisorProbe: 'passed', recorded: 'not_required' };
      if (this.verification.required) {
        const att = this.loadAtt();
        const check = checkAttestation(att, { dockerHost: this.cfg.dockerHost ?? null, imageIds }, 'maxAgeDays' in this.verification ? this.verification.maxAgeDays : 30);
        verification = { gvisorProbe: 'passed', recorded: check.ok.length ? 'valid' : 'missing_or_invalid', ...(att ? { recordedAt: att.createdAt } : {}) };
        if (check.ok.length === 0) return { ...base, reason: check.reason ?? 'The sandbox has not been verified.', verification };
        for (const eco of ECOSYSTEMS) {
          if (ecosystems[eco].available && !check.ok.includes(eco)) {
            ecosystems[eco] = { available: false, reason: `The ${eco} sandbox image changed since the sandbox was verified. Re-run "npm run sandbox -- --verify".` };
          }
        }
      }
    }

    let dependencyFetch = false;
    let dependencyFetchReason: string | undefined =
      'No registry egress proxy is configured, so checks that must download dependencies are disabled.';
    if (this.cfg.fetchNetwork && this.cfg.fetchProxyUrl) {
      const net = await this.docker(['network', 'inspect', '--format', '{{json .Internal}}', this.cfg.fetchNetwork]);
      if (net.code !== 0) dependencyFetchReason = 'The dependency-fetch network is missing on the sandbox host.';
      else if (net.stdout.trim() !== 'true') {
        dependencyFetchReason = 'The dependency-fetch network is not an internal network, so it is not used.';
      } else {
        dependencyFetch = true;
        dependencyFetchReason = undefined;
      }
    }

    const anyImage = ECOSYSTEMS.some((e) => ecosystems[e].available);
    return {
      ...base,
      verification,
      available: anyImage,
      ...(anyImage ? {} : { reason: 'No sandbox images are installed on the sandbox host.' }),
      dependencyFetch,
      ...(dependencyFetchReason ? { dependencyFetchReason } : {}),
      ecosystems,
    };
  }

  async execute(req: ExecuteRequest): Promise<ExecuteResult> {
    const tag = randomBytes(8).toString('hex');
    this.active.add(tag);
    const volume = `unbox-${tag}`;
    const keeper = `unbox-${tag}-keeper`;
    const names: string[] = [keeper];
    const image = this.cfg.images[req.ecosystem];
    const spec = (name: string, argv: readonly string[], env: Record<string, string>, network: string, workdir: string) => ({
      name,
      tag,
      runtime: this.cfg.runtime,
      image,
      network,
      volume,
      argv,
      env,
      workdir,
      limits: this.limits,
    });

    let result: ExecuteResult = { outcome: 'unavailable', cleanup: 'not_needed', message: 'The sandbox did not start.' };
    try {
      if (req.signal.aborted) return { outcome: 'cancelled', cleanup: 'not_needed' };
      req.onPhase('preparing');
      req.onSystem(`Creating an isolated workspace (${this.label()})`);
      const vol = await this.docker([
        'volume', 'create', '--driver', 'local',
        '--opt', 'type=tmpfs', '--opt', 'device=tmpfs',
        '--opt', `o=size=${this.limits.runWorkspaceMiB}m,uid=${SANDBOX_UID},gid=${SANDBOX_UID},mode=0700`,
        '--label', MANAGED_LABEL, '--label', `unbox.run=${tag}`,
        volume,
      ]);
      if (vol.code !== 0) return (result = { outcome: 'unavailable', failedStep: 'prepare', message: 'The sandbox could not create a workspace.', cleanup: 'not_needed' });

      const keep = await this.docker([...buildRunArgs({ ...spec(keeper, ['sleep', 'infinity'], {}, 'none', WORK.root), detach: true })]);
      if (keep.code !== 0) return (result = { outcome: 'unavailable', failedStep: 'prepare', message: 'The sandbox could not start.', cleanup: 'not_needed' });

      // Unpack the sanitized source inside the sandbox (never on this host).
      const prepName = `unbox-${tag}-prepare`;
      names.push(prepName);
      const prepArgs = buildRunArgs({
        ...spec(prepName, ['tar', '-x', '-f', '-', '-C', WORK.root, '--no-same-owner'], {}, 'none', WORK.root),
        interactive: true,
      });
      const prep = await this.runContainer(prepName, prepArgs, PREPARE_TIMEOUT_MS, req, { stdin: req.source, quiet: true });
      if (prep.kind !== 'exited') return (result = this.interrupted(prep.kind, 'prepare'));
      if (prep.code !== 0) {
        return (result = { outcome: 'unavailable', failedStep: 'prepare', exitCode: prep.code ?? -1, message: 'The source could not be unpacked in the sandbox.', cleanup: 'not_needed' });
      }

      const total = req.steps.length;
      for (let i = 0; i < total; i++) {
        const step = req.steps[i] as StepPlan;
        req.onPhase(step.kind === 'install' ? 'installing' : 'running');
        req.onSystem(`Step ${i + 1}/${total}: ${step.title}`);
        req.onSystem(`$ ${step.argv.join(' ')}`);
        req.onSystem(step.network === 'none' ? 'Network: none' : 'Network: package-registry proxy only');
        const env = { ...step.env };
        let network = 'none';
        if (step.network === 'registry-proxy') {
          if (!this.cfg.fetchNetwork || !this.cfg.fetchProxyUrl) {
            return (result = { outcome: 'unavailable', failedStep: 'install', message: 'Dependency download is not configured on this deployment.', cleanup: 'not_needed' });
          }
          network = this.cfg.fetchNetwork;
          Object.assign(env, { HTTPS_PROXY: this.cfg.fetchProxyUrl, https_proxy: this.cfg.fetchProxyUrl, NO_PROXY: '', no_proxy: '' });
        }
        const name = `unbox-${tag}-s${i}`;
        names.push(name);
        const timeoutSec = step.kind === 'install' ? this.limits.installTimeoutSec : this.limits.checkTimeoutSec;
        const r = await this.runContainer(name, buildRunArgs(spec(name, step.argv, env, network, WORK.src)), timeoutSec * 1000, req, {});
        const stepName = step.kind === 'install' ? 'install' : 'check';
        if (r.kind !== 'exited') return (result = this.interrupted(r.kind, stepName, timeoutSec));
        if (r.code === 125) {
          return (result = { outcome: 'unavailable', failedStep: stepName, exitCode: 125, message: 'The sandbox could not run this step.', cleanup: 'not_needed' });
        }
        if (r.code !== 0) {
          return (result = {
            outcome: 'failed',
            failedStep: stepName,
            exitCode: r.code ?? -1,
            message: describeExit(r.code, stepName),
            cleanup: 'not_needed',
          });
        }
      }
      result = { outcome: 'succeeded', exitCode: 0, cleanup: 'not_needed' };
      if (req.collect) {
        const dir = req.collect.dir;
        if (!SAFE_DIR_RE.test(dir) || dir.split('/').includes('..')) {
          result.artifactError = 'The build output directory is not a plain relative path.';
          return result;
        }
        req.onSystem(`Collecting build output from ${dir}/`);
        const name = `unbox-${tag}-collect`;
        names.push(name);
        const args = buildRunArgs(spec(name, ['tar', '-c', '-f', '-', '-C', `${WORK.src}/${dir}`, '.'], {}, 'none', WORK.root));
        const c = await this.captureContainer(name, args, PREPARE_TIMEOUT_MS, req, req.collect.maxBytes);
        if (c.kind === 'cancelled') return (result = this.interrupted('cancelled', 'check'));
        if (c.kind === 'too_large') result.artifactError = `The build output is larger than the ${Math.round(req.collect.maxBytes / 1048576)} MB preview limit.`;
        else if (c.kind === 'exited' && c.code === 0) result.artifact = c.data;
        else result.artifactError = `The build did not produce ${dir}/, or it could not be read.`;
      }
      return result;
    } finally {
      result.cleanup = await this.cleanup(tag, names, volume);
      this.active.delete(tag);
      if (result.cleanup === 'unconfirmed') {
        req.onSystem('Sandbox cleanup could not be confirmed; leftovers will be removed by the periodic sweep.');
      }
    }
  }

  /** Run a container and capture its stdout (bounded), for build artifacts. */
  private async captureContainer(
    name: string,
    args: string[],
    timeoutMs: number,
    req: ExecuteRequest,
    maxBytes: number,
  ): Promise<{ kind: 'exited'; code: number | null; data: Buffer } | { kind: 'timeout' | 'cancelled' | 'too_large' }> {
    const p = this.exec.spawn(this.cfg.dockerBin, args);
    p.stdin.end();
    const chunks: Buffer[] = [];
    let size = 0;
    let stopped: 'timeout' | 'cancelled' | 'too_large' | null = null;
    const stop = (why: 'timeout' | 'cancelled' | 'too_large') => {
      if (stopped) return;
      stopped = why;
      void this.docker(['rm', '-f', name]).finally(() => p.kill());
    };
    p.stdout.on('data', (c: Buffer) => {
      size += c.length;
      if (size > maxBytes) stop('too_large');
      else chunks.push(c);
    });
    p.stderr.on('data', () => {});
    const timer = setTimeout(() => stop('timeout'), timeoutMs);
    const onAbort = () => stop('cancelled');
    req.signal.addEventListener('abort', onAbort, { once: true });
    const code = await p.exited;
    clearTimeout(timer);
    req.signal.removeEventListener('abort', onAbort);
    if (stopped) return { kind: stopped };
    return { kind: 'exited', code, data: Buffer.concat(chunks, size) };
  }

  private interrupted(kind: 'timeout' | 'cancelled', step: 'prepare' | 'install' | 'check', timeoutSec?: number): ExecuteResult {
    if (kind === 'cancelled') return { outcome: 'cancelled', failedStep: step, message: 'Cancelled by the user.', cleanup: 'not_needed' };
    return {
      outcome: 'timed_out',
      failedStep: step,
      message: timeoutSec ? `The ${step} step exceeded its ${timeoutSec}s limit and the sandbox was stopped.` : `The ${step} step took too long and the sandbox was stopped.`,
      cleanup: 'not_needed',
    };
  }

  /** Run one container to completion, honouring timeout and cancellation by force-removing it. */
  private async runContainer(
    name: string,
    args: string[],
    timeoutMs: number,
    req: ExecuteRequest,
    opts: { stdin?: Buffer; quiet?: boolean },
  ): Promise<{ kind: 'exited'; code: number | null } | { kind: 'timeout' | 'cancelled' }> {
    const p = this.exec.spawn(this.cfg.dockerBin, args);
    if (opts.stdin) {
      Readable.from([opts.stdin]).pipe(zlib.createGunzip()).on('error', () => p.kill()).pipe(p.stdin);
    } else {
      p.stdin.end();
    }
    const streamName = (s: string) => `${name}:${s}`;
    p.stdout.on('data', (c: Buffer) => !opts.quiet && req.onOutput(streamName('out'), c));
    p.stderr.on('data', (c: Buffer) => {
      if (opts.quiet) return;
      // The Docker CLI writes its own errors to stderr; never forward those (they can include host details).
      if (/^docker: |Error response from daemon/.test(c.toString('utf8', 0, 64))) {
        req.onSystem('The sandbox reported an internal error (details are in the server log).');
        return;
      }
      req.onOutput(streamName('err'), c);
    });

    let interrupted: 'timeout' | 'cancelled' | null = null;
    const stop = (why: 'timeout' | 'cancelled') => {
      if (interrupted) return;
      interrupted = why;
      // Removing the container kills its whole process tree; then stop the CLI.
      void this.docker(['rm', '-f', name]).finally(() => p.kill());
    };
    const timer = setTimeout(() => stop('timeout'), timeoutMs);
    const onAbort = () => stop('cancelled');
    req.signal.addEventListener('abort', onAbort, { once: true });
    if (req.signal.aborted) onAbort();
    const code = await p.exited;
    clearTimeout(timer);
    req.signal.removeEventListener('abort', onAbort);
    if (!opts.quiet) {
      req.onOutputEnd(streamName('out'));
      req.onOutputEnd(streamName('err'));
    }
    if (interrupted) return { kind: interrupted };
    return { kind: 'exited', code };
  }

  private async cleanup(tag: string, names: string[], volume: string): Promise<'confirmed' | 'unconfirmed'> {
    await this.docker(['rm', '-f', ...names]);
    await this.docker(['volume', 'rm', '-f', volume]);
    const ps = await this.docker(['ps', '-a', '-q', '--filter', `label=unbox.run=${tag}`]);
    const vols = await this.docker(['volume', 'ls', '-q', '--filter', `label=unbox.run=${tag}`]);
    const clean = ps.code === 0 && vols.code === 0 && ps.stdout.trim() === '' && vols.stdout.trim() === '';
    return clean ? 'confirmed' : 'unconfirmed';
  }

  async sweep(): Promise<void> {
    const activeTags = this.active;
    const ps = await this.docker(['ps', '-a', '--filter', `label=${MANAGED_LABEL}`, '--format', '{{.Names}}\t{{.Label "unbox.run"}}']);
    if (ps.code === 0) {
      const stale = ps.stdout
        .split('\n')
        .map((l) => l.split('\t'))
        .filter(([n, t]) => n && t && /^[a-f0-9]{16}$/.test(t) && !activeTags.has(t))
        .map(([n]) => n as string)
        .filter((n) => /^unbox-[a-f0-9]{16}-[a-z0-9]+$/.test(n));
      if (stale.length > 0) await this.docker(['rm', '-f', ...stale]);
    }
    const vols = await this.docker(['volume', 'ls', '--filter', `label=${MANAGED_LABEL}`, '--format', '{{.Name}}']);
    if (vols.code === 0) {
      const stale = vols.stdout
        .split('\n')
        .map((v) => v.trim())
        .filter((v) => /^unbox-[a-f0-9]{16}$/.test(v) && !activeTags.has(v.slice('unbox-'.length)));
      if (stale.length > 0) await this.docker(['volume', 'rm', '-f', ...stale]);
    }
  }
}

function describeExit(code: number | null, step: 'install' | 'check'): string {
  if (code === 137) return `The ${step} step was killed (exit 137). This usually means it ran out of memory.`;
  if (code === 126 || code === 127) return `The ${step} command could not be started in the sandbox image (exit ${code}).`;
  if (step === 'install') return `Dependency installation failed (exit ${code ?? 'unknown'}).`;
  return `The check finished with exit code ${code ?? 'unknown'}.`;
}
