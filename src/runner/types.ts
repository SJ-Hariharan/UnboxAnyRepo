import type { Ecosystem } from '../config.ts';
import type { StepPlan } from '../checks/types.ts';

export type Isolation = 'strong' | 'unsafe-local' | 'none';

export interface RunnerStatus {
  available: boolean;
  isolation: Isolation;
  /** Short human label, e.g. "Docker + gVisor (runsc)". */
  label: string;
  /** Why execution is unavailable (safe to show to users). */
  reason?: string;
  dependencyFetch: boolean;
  dependencyFetchReason?: string;
  ecosystems: Record<Ecosystem, { available: boolean; reason?: string }>;
  limits?: { cpus: number; memoryMiB: number; pids: number; workspaceMiB: number; installTimeoutSec: number; checkTimeoutSec: number };
}

export type Phase = 'preparing' | 'installing' | 'running';
export type Outcome = 'succeeded' | 'failed' | 'timed_out' | 'cancelled' | 'unavailable';

export interface ExecuteRequest {
  ecosystem: Ecosystem;
  steps: StepPlan[];
  /** Sanitized tar.gz produced by the archive layer. */
  source: Buffer;
  signal: AbortSignal;
  onPhase(phase: Phase): void;
  /** Raw process output (stream name, bytes) — sanitized by the caller. */
  onOutput(stream: string, chunk: Buffer): void;
  onOutputEnd(stream: string): void;
  /** Messages from the runner itself. */
  onSystem(text: string): void;
}

export interface ExecuteResult {
  outcome: Outcome;
  exitCode?: number;
  failedStep?: 'prepare' | 'install' | 'check';
  /** Safe, user-facing explanation. */
  message?: string;
  /** Whether the runner confirmed all sandbox resources were removed. */
  cleanup: 'confirmed' | 'unconfirmed' | 'not_needed';
}

export interface Runner {
  readonly kind: string;
  status(force?: boolean): Promise<RunnerStatus>;
  execute(req: ExecuteRequest): Promise<ExecuteResult>;
  /** Remove sandbox leftovers (e.g. after a crash), never touching runs in flight. */
  sweep?(): Promise<void>;
}
