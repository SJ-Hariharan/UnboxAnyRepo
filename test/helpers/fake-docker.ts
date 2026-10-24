/**
 * Fake Docker CLI for runner tests. Records every invocation, simulates
 * containers/volumes, and lets a step "hang" until `docker rm -f` kills it —
 * the same way a real container's process tree dies with the container.
 */
import { PassThrough } from 'node:stream';
import zlib from 'node:zlib';
import type { CommandExecutor, Spawned, RunResult } from '../../src/runner/exec.ts';

export interface StepScript {
  stdout?: string[];
  stderr?: string[];
  exitCode?: number;
  hang?: boolean;
}

export interface FakeDockerOptions {
  runtimes?: string[];
  images?: string[];
  networks?: Record<string, { internal: boolean }>;
  /** Keyed by the step's command line (entrypoint + args joined by spaces). */
  steps?: Record<string, StepScript>;
  failVolumeCreate?: boolean;
  /** Leftovers from a "previous crash". */
  containers?: { name: string; tag: string }[];
  volumes?: string[];
  unreachable?: boolean;
  /** What the kernel-log probe prints: gVisor (default) or a normal Linux kernel. */
  kernel?: 'gvisor' | 'linux';
  imageIds?: Record<string, string>;
  /** Bytes a `tar -c` (build output collection) container writes to stdout. */
  artifact?: Buffer;
}

export class FakeDocker implements CommandExecutor {
  readonly calls: string[][] = [];
  readonly bins = new Set<string>();
  readonly containers = new Map<string, { tag: string; kill?: () => void }>();
  readonly volumes = new Set<string>();
  stdinReceived: Buffer | null = null;
  private readonly o: FakeDockerOptions;

  constructor(o: FakeDockerOptions = {}) {
    this.o = o;
    for (const c of o.containers ?? []) this.containers.set(c.name, { tag: c.tag });
    for (const v of o.volumes ?? []) this.volumes.add(v);
  }

  private flag(args: readonly string[], name: string): string | undefined {
    const i = args.indexOf(name);
    return i === -1 ? undefined : args[i + 1];
  }

  /** The command a `docker run` would execute: --entrypoint + args after the image. */
  commandOf(args: readonly string[]): string {
    const entry = this.flag(args, '--entrypoint') ?? '';
    // image is the first arg after the last flag pair; find by our known structure: after all "--x value" pairs.
    let i = 1;
    const valueFlags = new Set([
      '--name', '--label', '--runtime', '--pull', '--network', '--user', '--cap-drop', '--security-opt', '--tmpfs',
      '--memory', '--memory-swap', '--cpus', '--pids-limit', '--ulimit', '--ipc', '--hostname', '--log-driver',
      '--mount', '--workdir', '--entrypoint', '--env',
    ]);
    while (i < args.length) {
      const a = args[i] as string;
      if (valueFlags.has(a)) i += 2;
      else if (a === '--rm' || a === '-d' || a === '-i' || a === '--read-only') i += 1;
      else break;
    }
    return [entry, ...args.slice(i + 1)].join(' ');
  }

  async run(bin: string, args: readonly string[]): Promise<RunResult> {
    this.bins.add(bin);
    this.calls.push([...args]);
    const ok = (stdout = ''): RunResult => ({ code: 0, stdout, stderr: '', timedOut: false });
    const fail = (): RunResult => ({ code: 1, stdout: '', stderr: 'error', timedOut: false });
    if (this.o.unreachable) return fail();
    const [cmd, sub] = args;
    if (cmd === 'info') return ok(JSON.stringify(Object.fromEntries((this.o.runtimes ?? ['runsc', 'runc']).map((r) => [r, {}]))));
    if (cmd === 'image' && sub === 'inspect') {
      const img = args.at(-1) as string;
      return (this.o.images ?? []).includes(img) ? ok(`${this.o.imageIds?.[img] ?? 'sha256:x'}\n`) : fail();
    }
    if (cmd === 'run' && args.includes('--entrypoint') && this.flag(args, '--entrypoint') === 'dmesg') {
      return ok(this.o.kernel === 'linux' ? '[    0.000000] Linux version 6.10.0\n' : '[    0.000000] Starting gVisor...\n');
    }
    if (cmd === 'network' && sub === 'inspect') {
      const n = this.o.networks?.[args.at(-1) as string];
      return n ? ok(String(n.internal)) : fail();
    }
    if (cmd === 'volume' && sub === 'create') {
      if (this.o.failVolumeCreate) return fail();
      this.volumes.add(args.at(-1) as string);
      return ok();
    }
    if (cmd === 'volume' && sub === 'rm') {
      for (const v of args.slice(3)) this.volumes.delete(v);
      return ok();
    }
    if (cmd === 'volume' && sub === 'ls') {
      const tagFilter = /label=unbox\.run=(\w+)/.exec(args.join(' '))?.[1];
      const list = [...this.volumes].filter((v) => !tagFilter || v === `unbox-${tagFilter}`);
      return ok(list.join('\n'));
    }
    if (cmd === 'run' && args.includes('-d')) {
      const name = this.flag(args, '--name') as string;
      this.containers.set(name, { tag: /unbox-([a-f0-9]{16})/.exec(name)?.[1] ?? '' });
      return ok('cid');
    }
    if (cmd === 'rm') {
      for (const n of args.slice(2)) {
        const c = this.containers.get(n);
        c?.kill?.();
        this.containers.delete(n);
      }
      return ok();
    }
    if (cmd === 'ps') {
      const tagFilter = /label=unbox\.run=(\w+)/.exec(args.join(' '))?.[1];
      const rows = [...this.containers].filter(([, c]) => !tagFilter || c.tag === tagFilter);
      if (args.includes('--format')) return ok(rows.map(([n, c]) => `${n}\t${c.tag}`).join('\n'));
      return ok(rows.map(([n]) => n).join('\n'));
    }
    return fail();
  }

  spawn(bin: string, args: readonly string[]): Spawned {
    this.bins.add(bin);
    this.calls.push([...args]);
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const stdin = new PassThrough();
    const name = this.flag(args, '--name') ?? '';
    const tag = /unbox-([a-f0-9]{16})/.exec(name)?.[1] ?? '';
    let resolveExit: (code: number | null) => void = () => {};
    const exited = new Promise<number | null>((r) => (resolveExit = r));
    let done = false;
    const finish = (code: number | null) => {
      if (done) return;
      done = true;
      this.containers.delete(name);
      stdout.end();
      stderr.end();
      resolveExit(code);
    };
    this.containers.set(name, { tag, kill: () => finish(137) });

    const command = this.commandOf(args);
    if (command.startsWith('tar -c')) {
      stdin.resume();
      setImmediate(() => {
        if (this.o.artifact) stdout.write(this.o.artifact);
        setImmediate(() => finish(this.o.artifact ? 0 : 2));
      });
    } else if (command.startsWith('tar ')) {
      const chunks: Buffer[] = [];
      stdin.on('data', (c: Buffer) => chunks.push(c));
      stdin.on('end', () => {
        this.stdinReceived = Buffer.concat(chunks);
        finish(0);
      });
    } else {
      stdin.resume();
      const script = this.o.steps?.[command] ?? { exitCode: 0 };
      setImmediate(() => {
        for (const line of script.stdout ?? []) stdout.write(line);
        for (const line of script.stderr ?? []) stderr.write(line);
        if (!script.hang) setImmediate(() => finish(script.exitCode ?? 0));
      });
    }
    return { stdout, stderr, stdin, exited, kill: () => finish(null) };
  }

  /** All `docker run` invocations for workload steps (not keeper/prepare). */
  stepRuns(): string[][] {
    return this.calls.filter((c) => c[0] === 'run' && !c.includes('-d') && !c.includes('-i'));
  }
}

export function gunzipTar(buf: Buffer): Buffer {
  return zlib.gunzipSync(buf);
}
