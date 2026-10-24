/**
 * Run lifecycle: validation, queueing, execution through the runner adapter,
 * cancellation, a watchdog, retention, and per-session authorization.
 */
import type { Limits } from '../config.ts';
import type { CheckOption, CheckId } from '../checks/types.ts';
import { isCheckId } from '../checks/types.ts';
import type { Runner, Outcome, Isolation } from '../runner/types.ts';
import type { Inspection } from './inspections.ts';
import { RunLog } from './logs.ts';
import type { LogLine } from './logs.ts';
import { newId } from './ids.ts';

export type RunState = 'queued' | 'preparing' | 'installing' | 'running' | Outcome;
const TERMINAL: ReadonlySet<RunState> = new Set(['succeeded', 'failed', 'timed_out', 'cancelled', 'unavailable']);

export class RunError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, status: number, message: string) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

interface RunRecord {
  id: string;
  sessionId: string;
  state: RunState;
  repo: { fullName: string; htmlUrl: string };
  commitSha: string;
  demo: boolean;
  check: CheckOption;
  createdAt: number;
  startedAt?: number;
  finishedAt?: number;
  exitCode?: number;
  failedStep?: string;
  message?: string;
  cleanup?: string;
  isolation: Isolation;
  runnerLabel: string;
  cancelRequested: boolean;
  log: RunLog;
  abort: AbortController;
  source: Buffer | null;
  listeners: Set<(e: RunEvent) => void>;
  preview?: { dir: string; maxBytes: number };
  previewToken?: string;
  previewError?: string;
}

export interface RunView {
  id: string;
  state: RunState;
  terminal: boolean;
  repo: { fullName: string; htmlUrl: string };
  commitSha: string;
  demo: boolean;
  check: { id: CheckId; title: string; ecosystem: string; installsDependencies: boolean };
  steps: { kind: string; title: string; argv: string[]; network: string }[];
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  durationMs?: number;
  queuePosition?: number;
  exitCode?: number;
  failedStep?: string;
  message?: string;
  cleanup?: string;
  isolation: Isolation;
  runnerLabel: string;
  cancelRequested: boolean;
  log: { truncated: boolean; receivedBytes: number };
  nextSteps: string[];
  /** Build previews: requested, then either a token or an explanation. */
  preview?: { requested: true; token?: string; error?: string };
}

export type RunEvent = { type: 'state'; run: RunView } | { type: 'log'; lines: LogLine[] } | { type: 'truncated' };

export interface CreateRunInput {
  sessionId: string;
  inspection: Inspection;
  checkId: unknown;
  acknowledged: unknown;
  /** Collect this output directory after a successful run, for a build preview. */
  preview?: { dir: string; maxBytes: number };
}

export type ArtifactHandler = (run: { id: string; sessionId: string; inspectionId: string; repo: { fullName: string }; commitSha: string; dir: string }, artifact: Buffer) => Promise<string>;

export class RunManager {
  private readonly runs = new Map<string, RunRecord>();
  private readonly queue: string[] = [];
  private active = 0;
  private readonly runner: Runner;
  private readonly limits: Limits;
  private readonly secretValues: readonly string[];
  private readonly watchdogMarginSec: number;

  private readonly onArtifact: ArtifactHandler | undefined;
  private readonly inspectionOf = new Map<string, string>();

  constructor(opts: { runner: Runner; limits: Limits; secretValues: readonly string[]; watchdogMarginSec?: number; onArtifact?: ArtifactHandler }) {
    this.onArtifact = opts.onArtifact;
    this.runner = opts.runner;
    this.limits = opts.limits;
    this.secretValues = opts.secretValues;
    this.watchdogMarginSec = opts.watchdogMarginSec ?? 300;
  }

  async create(input: CreateRunInput): Promise<RunView> {
    const { inspection, sessionId } = input;
    if (!isCheckId(input.checkId)) throw new RunError('unknown_check', 400, 'Choose one of the proposed checks.');
    const check = inspection.detection.checks.find((c) => c.id === input.checkId);
    if (!check) throw new RunError('unknown_check', 400, 'That check was not proposed for this repository.');
    if (!check.available) throw new RunError('check_unavailable', 409, check.unavailableReason ?? 'That check is not available for this repository.');
    if (input.acknowledged !== true) {
      throw new RunError('ack_required', 400, 'Confirm that you understand repository code will run in the sandbox.');
    }

    const status = await this.runner.status();
    if (!status.available) throw new RunError('execution_unavailable', 503, status.reason ?? 'Execution is unavailable.');
    const eco = status.ecosystems[check.ecosystem];
    if (!eco.available) throw new RunError('ecosystem_unavailable', 503, eco.reason ?? 'This ecosystem is not available on the sandbox host.');
    if (check.installsDependencies && !status.dependencyFetch) {
      throw new RunError('dependency_fetch_unavailable', 503, status.dependencyFetchReason ?? 'Dependency download is not available.');
    }

    for (const r of this.runs.values()) {
      if (r.sessionId === sessionId && !TERMINAL.has(r.state)) {
        throw new RunError('session_busy', 429, 'You already have a run in progress. Wait for it to finish or cancel it.');
      }
    }
    if (this.active >= this.limits.maxConcurrentRuns && this.queue.length >= this.limits.maxQueuedRuns) {
      throw new RunError('queue_full', 503, 'The sandbox is busy. Try again in a few minutes.');
    }

    const rec: RunRecord = {
      id: newId(),
      sessionId,
      state: 'queued',
      repo: { fullName: inspection.repo.fullName, htmlUrl: inspection.repo.htmlUrl },
      commitSha: inspection.commitSha,
      demo: inspection.demo,
      check,
      createdAt: Date.now(),
      isolation: status.isolation,
      runnerLabel: status.label,
      cancelRequested: false,
      log: new RunLog({ headBytes: this.limits.logHeadBytes, tailBytes: this.limits.logTailBytes, secretValues: this.secretValues }),
      abort: new AbortController(),
      source: inspection.sanitizedTarGz,
      listeners: new Set(),
      ...(input.preview ? { preview: input.preview } : {}),
    };
    this.inspectionOf.set(rec.id, inspection.id);
    rec.log.events = {
      onLine: (line) => this.emit(rec, { type: 'log', lines: [line] }),
      onTruncated: () => this.emit(rec, { type: 'truncated' }),
    };
    this.runs.set(rec.id, rec);
    rec.log.system(`Queued ${check.title} for ${rec.repo.fullName} at ${rec.commitSha.slice(0, 12)}`);
    this.queue.push(rec.id);
    this.pump();
    return this.view(rec);
  }

  /** Authorization: a run is only visible to the session that created it. */
  private owned(id: string, sessionId: string): RunRecord | undefined {
    const r = this.runs.get(id);
    return r && r.sessionId === sessionId ? r : undefined;
  }

  get(id: string, sessionId: string): RunView | undefined {
    const r = this.owned(id, sessionId);
    return r ? this.view(r) : undefined;
  }

  logLines(id: string, sessionId: string, after = 0): LogLine[] | undefined {
    const r = this.owned(id, sessionId);
    if (!r) return undefined;
    return TERMINAL.has(r.state) ? r.log.retained() : r.log.headSince(after);
  }

  logText(id: string, sessionId: string): string | undefined {
    return this.owned(id, sessionId)?.log.toText();
  }

  list(sessionId: string): RunView[] {
    return [...this.runs.values()]
      .filter((r) => r.sessionId === sessionId)
      .sort((a, b) => b.createdAt - a.createdAt)
      .map((r) => this.view(r));
  }

  subscribe(id: string, sessionId: string, fn: (e: RunEvent) => void): (() => void) | undefined {
    const r = this.owned(id, sessionId);
    if (!r) return undefined;
    r.listeners.add(fn);
    return () => r.listeners.delete(fn);
  }

  cancel(id: string, sessionId: string): RunView | undefined {
    const r = this.owned(id, sessionId);
    if (!r) return undefined;
    if (TERMINAL.has(r.state)) throw new RunError('already_finished', 409, 'This run has already finished.');
    const queuedAt = this.queue.indexOf(r.id);
    if (queuedAt !== -1) {
      this.queue.splice(queuedAt, 1);
      r.log.system('Cancelled before it started; nothing was executed.');
      this.finish(r, { state: 'cancelled', message: 'Cancelled before it started. No code was executed.', cleanup: 'not_needed' });
      return this.view(r);
    }
    if (!r.cancelRequested) {
      r.cancelRequested = true;
      r.log.system('Cancellation requested; stopping the sandbox…');
      r.abort.abort();
      this.emit(r, { type: 'state', run: this.view(r) });
    }
    return this.view(r);
  }

  get activeCount(): number {
    return this.active;
  }

  get queuedCount(): number {
    return this.queue.length;
  }

  purge(): void {
    const cutoff = Date.now() - this.limits.runRetentionSec * 1000;
    for (const [id, r] of this.runs) {
      if (TERMINAL.has(r.state) && (r.finishedAt ?? r.createdAt) < cutoff) {
        this.runs.delete(id);
        this.inspectionOf.delete(id);
      }
    }
  }

  private pump(): void {
    while (this.active < this.limits.maxConcurrentRuns && this.queue.length > 0) {
      const id = this.queue.shift() as string;
      const r = this.runs.get(id);
      if (!r || r.state !== 'queued') continue;
      this.active++;
      // Leave the queue immediately, but start on the next tick so callers can subscribe first.
      r.state = 'preparing';
      setImmediate(() => {
        void this.execute(r).finally(() => {
          this.active--;
          this.pump();
        });
      });
    }
    // Queue positions changed: let waiting clients know.
    for (const id of this.queue) {
      const r = this.runs.get(id);
      if (r) this.emit(r, { type: 'state', run: this.view(r) });
    }
  }

  private async execute(r: RunRecord): Promise<void> {
    r.startedAt = Date.now();
    this.emit(r, { type: 'state', run: this.view(r) });
    if (r.abort.signal.aborted) {
      this.finish(r, { state: 'cancelled', message: 'Cancelled before the sandbox started. No code was executed.', cleanup: 'not_needed' });
      return;
    }
    const source = r.source;
    if (!source) {
      this.finish(r, { state: 'unavailable', message: 'The repository snapshot is no longer available.', cleanup: 'not_needed' });
      return;
    }
    // Watchdog: a hard upper bound even if the runner misbehaves.
    const budgetMs = (this.limits.installTimeoutSec + this.limits.checkTimeoutSec + this.watchdogMarginSec) * 1000;
    let watchdogFired = false;
    const watchdog = setTimeout(() => {
      watchdogFired = true;
      r.abort.abort();
    }, budgetMs);
    try {
      const res = await this.runner.execute({
        ecosystem: r.check.ecosystem,
        steps: r.check.steps,
        source,
        signal: r.abort.signal,
        onPhase: (phase) => {
          if (TERMINAL.has(r.state)) return;
          r.state = phase;
          this.emit(r, { type: 'state', run: this.view(r) });
        },
        onOutput: (stream, chunk) => r.log.write(stream, chunk),
        onOutputEnd: (stream) => r.log.end(stream),
        onSystem: (text) => r.log.system(text),
        ...(r.preview ? { collect: r.preview } : {}),
      });
      if (r.preview && res.outcome === 'succeeded') {
        if (res.artifact && this.onArtifact) {
          try {
            r.previewToken = await this.onArtifact(
              { id: r.id, sessionId: r.sessionId, inspectionId: this.inspectionOf.get(r.id) ?? '', repo: r.repo, commitSha: r.commitSha, dir: r.preview.dir },
              res.artifact,
            );
            r.log.system('Build output collected; the preview is ready.');
          } catch (err) {
            r.previewError = err instanceof Error ? err.message : 'The preview could not be created.';
          }
        } else {
          r.previewError = res.artifactError ?? 'The build output could not be collected.';
        }
        if (r.previewError) r.log.system(`Preview not created: ${r.previewError}`);
      }
      let state: RunState = res.outcome;
      let message = res.message;
      if (watchdogFired && state === 'cancelled') {
        state = 'timed_out';
        message = 'The run exceeded its total time budget and the sandbox was stopped.';
      }
      if (state === 'cancelled') {
        message =
          res.cleanup === 'confirmed'
            ? 'Cancelled. The sandbox and every process in it were removed.'
            : 'Cancellation was requested, but removal of the sandbox could not be confirmed yet. It will be retried by the cleanup sweep.';
      }
      this.finish(r, {
        state,
        ...(message !== undefined ? { message } : {}),
        ...(res.exitCode !== undefined ? { exitCode: res.exitCode } : {}),
        ...(res.failedStep !== undefined ? { failedStep: res.failedStep } : {}),
        cleanup: res.cleanup,
      });
    } catch {
      this.finish(r, { state: 'unavailable', message: 'The sandbox failed unexpectedly. No result is available.', cleanup: 'unconfirmed' });
    } finally {
      clearTimeout(watchdog);
    }
  }

  private finish(r: RunRecord, f: { state: RunState; message?: string; exitCode?: number; failedStep?: string; cleanup?: string }): void {
    r.state = f.state;
    r.finishedAt = Date.now();
    if (f.message !== undefined) r.message = f.message;
    if (f.exitCode !== undefined) r.exitCode = f.exitCode;
    if (f.failedStep !== undefined) r.failedStep = f.failedStep;
    if (f.cleanup !== undefined) r.cleanup = f.cleanup;
    r.source = null; // release the snapshot
    const label: Record<string, string> = {
      succeeded: 'Check passed',
      failed: 'Check failed',
      timed_out: 'Timed out',
      cancelled: 'Cancelled',
      unavailable: 'Could not run',
    };
    r.log.system(`${label[f.state] ?? f.state}${r.exitCode !== undefined ? ` (exit code ${r.exitCode})` : ''}${r.message ? ` — ${r.message}` : ''}`);
    this.emit(r, { type: 'state', run: this.view(r) });
    r.listeners.clear();
  }

  private emit(r: RunRecord, e: RunEvent): void {
    for (const fn of r.listeners) {
      try {
        fn(e);
      } catch {
        /* a broken listener must not affect the run */
      }
    }
  }

  private view(r: RunRecord): RunView {
    const pos = this.queue.indexOf(r.id);
    const v: RunView = {
      id: r.id,
      state: r.state,
      terminal: TERMINAL.has(r.state),
      repo: r.repo,
      commitSha: r.commitSha,
      demo: r.demo,
      check: { id: r.check.id, title: r.check.title, ecosystem: r.check.ecosystem, installsDependencies: r.check.installsDependencies },
      steps: r.check.steps.map((s) => ({ kind: s.kind, title: s.title, argv: s.argv, network: s.network })),
      createdAt: new Date(r.createdAt).toISOString(),
      isolation: r.isolation,
      runnerLabel: r.runnerLabel,
      cancelRequested: r.cancelRequested,
      log: { truncated: r.log.isTruncated, receivedBytes: r.log.receivedBytes },
      nextSteps: nextSteps(r),
    };
    if (r.preview) v.preview = { requested: true, ...(r.previewToken ? { token: r.previewToken } : {}), ...(r.previewError ? { error: r.previewError } : {}) };
    if (r.startedAt) v.startedAt = new Date(r.startedAt).toISOString();
    if (r.finishedAt) v.finishedAt = new Date(r.finishedAt).toISOString();
    if (r.startedAt && r.finishedAt) v.durationMs = r.finishedAt - r.startedAt;
    if (pos !== -1) v.queuePosition = pos + 1;
    if (r.exitCode !== undefined) v.exitCode = r.exitCode;
    if (r.failedStep !== undefined) v.failedStep = r.failedStep;
    if (r.message !== undefined) v.message = r.message;
    if (r.cleanup !== undefined) v.cleanup = r.cleanup;
    return v;
  }
}

function nextSteps(r: RunRecord): string[] {
  switch (r.state) {
    case 'succeeded':
      return [
        'The check passed in this sandbox at this exact commit. That does not mean the code is safe to run on your machine.',
        "Compare with the project's own CI for the same commit; results can differ with other toolchains or settings.",
      ];
    case 'failed':
      return r.failedStep === 'install'
        ? [
            'Installation may need things this sandbox deliberately blocks: install scripts, native builds, git or private registries.',
            'Check the log for the first error; a project-specific setup step may be required.',
          ]
        : [
            'Tests can fail here because there is no network, no services (databases, browsers) and no secrets.',
            "Check the log for the first failure, and the project's contributing guide for test prerequisites.",
          ];
    case 'timed_out':
      return ['Large suites can exceed the time limit. A build or vet check, if offered, is usually faster.'];
    case 'unavailable':
      return ['Nothing ran to completion, so there is no result. Try again later or choose another check.'];
    case 'cancelled':
      return ['You can start the check again from the same inspection while it is still available.'];
    default:
      return [];
  }
}
