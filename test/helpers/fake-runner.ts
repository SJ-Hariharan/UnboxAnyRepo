/** Scripted runner for manager/API/UI tests. Executes nothing. */
import type { Runner, RunnerStatus, ExecuteRequest, ExecuteResult } from '../../src/runner/types.ts';

export interface FakeScript {
  lines?: string[];
  delayMs?: number;
  /** Wait for cancellation instead of finishing. */
  hang?: boolean;
  result?: Partial<ExecuteResult>;
  /** Ignore abort signals (simulates a runner that cannot stop). */
  ignoreAbort?: boolean;
  /** Returned as the build artifact when the request asks to collect output. */
  artifact?: Buffer;
}

export class FakeRunner implements Runner {
  readonly kind = 'fake';
  executions = 0;
  statusOverride: Partial<RunnerStatus> = {};
  script: FakeScript = { lines: ['ok\n'] };
  private readonly pending = new Set<() => void>();

  /** Restore the default script and end every run still waiting, as if cancelled. Call between tests. */
  reset(): void {
    this.script = { lines: ['ok\n'] };
    this.statusOverride = {};
    for (const release of this.pending) release();
    this.pending.clear();
  }

  async status(): Promise<RunnerStatus> {
    return {
      available: true,
      isolation: 'strong',
      label: 'Test sandbox',
      dependencyFetch: true,
      ecosystems: { node: { available: true }, python: { available: true }, go: { available: true }, rust: { available: true } },
      ...this.statusOverride,
    };
  }

  async execute(req: ExecuteRequest): Promise<ExecuteResult> {
    this.executions++;
    const s = this.script;
    req.onPhase('preparing');
    req.onSystem(`Creating an isolated workspace (${this.statusOverride.label ?? 'Test sandbox'})`);
    for (const step of req.steps) {
      req.onPhase(step.kind === 'install' ? 'installing' : 'running');
      req.onSystem(`$ ${step.argv.join(' ')}`);
    }
    for (const l of s.lines ?? []) req.onOutput('out', Buffer.from(l));
    req.onOutputEnd('out');
    let release = () => {};
    const wait = new Promise<'aborted' | 'done'>((resolve) => {
      release = () => resolve('aborted');
      this.pending.add(release);
      if (!s.ignoreAbort) req.signal.addEventListener('abort', () => resolve('aborted'), { once: true });
      if (!s.hang) setTimeout(() => resolve('done'), s.delayMs ?? 5);
    });
    const how = await wait;
    this.pending.delete(release);
    if (how === 'aborted') return { outcome: 'cancelled', cleanup: 'confirmed' };
    const collected = req.collect ? (s.artifact ? { artifact: s.artifact } : { artifactError: 'The build did not produce output.' }) : {};
    return { outcome: 'succeeded', exitCode: 0, cleanup: 'confirmed', ...collected, ...s.result };
  }
}
