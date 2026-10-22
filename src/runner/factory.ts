/**
 * Chooses the runner. Fails closed: anything short of a correctly configured
 * strong sandbox yields a runner that refuses to execute, with a reason the UI
 * can show. There is no host-execution fallback anywhere in this codebase.
 */
import type { Config } from '../config.ts';
import { DockerRunner } from './docker.ts';
import { ProcessExecutor, minimalEnv } from './exec.ts';
import type { CommandExecutor } from './exec.ts';
import type { Runner, RunnerStatus, ExecuteResult } from './types.ts';

export class DisabledRunner implements Runner {
  readonly kind = 'disabled';
  private readonly reason: string;
  constructor(reason: string) {
    this.reason = reason;
  }
  async status(): Promise<RunnerStatus> {
    return {
      available: false,
      isolation: 'none',
      label: 'Execution disabled',
      reason: this.reason,
      dependencyFetch: false,
      dependencyFetchReason: this.reason,
      ecosystems: {
        node: { available: false },
        python: { available: false },
        go: { available: false },
        rust: { available: false },
      },
    };
  }
  async execute(): Promise<ExecuteResult> {
    return { outcome: 'unavailable', message: this.reason, cleanup: 'not_needed' };
  }
}

export function createRunner(config: Config, exec?: CommandExecutor): Runner {
  const r = config.runner;
  if (r.mode === 'disabled') {
    return new DisabledRunner('Execution is disabled on this deployment. You can still inspect repositories and review the planned checks.');
  }
  if (r.runtime === 'runc') {
    if (!r.unsafeLocalAcknowledged) {
      return new DisabledRunner(
        'The runc runtime is not a strong sandbox. It is only allowed for local development with REPORADAR_ALLOW_UNSAFE_LOCAL_RUNNER set.',
      );
    }
    if (config.production) {
      return new DisabledRunner('The unsafe local runner cannot be used when NODE_ENV=production.');
    }
  }
  const executor = exec ?? new ProcessExecutor(minimalEnv(r.dockerHost ? { DOCKER_HOST: r.dockerHost } : {}));
  return new DockerRunner({
    config: r,
    limits: config.limits,
    isolation: r.runtime === 'runsc' ? 'strong' : 'unsafe-local',
    exec: executor,
  });
}
