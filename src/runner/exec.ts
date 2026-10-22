/**
 * Process execution with argv arrays only (never a shell), a minimal
 * environment, and hard timeouts. Injectable so the runner can be tested.
 */
import { spawn } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';

export interface Spawned {
  stdout: Readable;
  stderr: Readable;
  stdin: Writable;
  /** Resolves with the exit code (null when killed by a signal). */
  exited: Promise<number | null>;
  kill(): void;
}

export interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export interface CommandExecutor {
  spawn(bin: string, args: readonly string[]): Spawned;
  run(bin: string, args: readonly string[], timeoutMs: number): Promise<RunResult>;
}

/** Environment passed to the Docker CLI: only what it needs, never app secrets. */
export function minimalEnv(extra: Record<string, string | undefined> = {}): Record<string, string> {
  const env: Record<string, string> = { PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin' };
  for (const key of ['HOME', 'DOCKER_CONFIG', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY', 'DOCKER_CONTEXT']) {
    const v = process.env[key];
    if (v) env[key] = v;
  }
  for (const [k, v] of Object.entries(extra)) if (v !== undefined) env[k] = v;
  return env;
}

export class ProcessExecutor implements CommandExecutor {
  private readonly env: Record<string, string>;
  constructor(env: Record<string, string>) {
    this.env = env;
  }

  spawn(bin: string, args: readonly string[]): Spawned {
    const child = spawn(bin, [...args], { shell: false, env: this.env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    const exited = new Promise<number | null>((resolve) => {
      child.on('error', () => resolve(127));
      child.on('close', (code) => resolve(code));
    });
    child.stdin.on('error', () => {
      /* sandbox closed stdin early; handled via exit code */
    });
    return {
      stdout: child.stdout,
      stderr: child.stderr,
      stdin: child.stdin,
      exited,
      kill: () => {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      },
    };
  }

  async run(bin: string, args: readonly string[], timeoutMs: number): Promise<RunResult> {
    const p = this.spawn(bin, args);
    p.stdin.end();
    let stdout = '';
    let stderr = '';
    const cap = 1024 * 1024;
    p.stdout.on('data', (c: Buffer) => {
      if (stdout.length < cap) stdout += c.toString('utf8');
    });
    p.stderr.on('data', (c: Buffer) => {
      if (stderr.length < cap) stderr += c.toString('utf8');
    });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      p.kill();
    }, timeoutMs);
    const code = await p.exited;
    clearTimeout(timer);
    return { code, stdout, stderr, timedOut };
  }
}
