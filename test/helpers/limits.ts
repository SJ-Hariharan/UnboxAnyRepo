import { loadConfig } from '../../src/config.ts';
import type { Config, Limits } from '../../src/config.ts';

export function testConfig(env: Record<string, string> = {}): Config {
  return loadConfig({ REPORADAR_GITHUB_SOURCE: 'fixtures', ...env });
}

export function testLimits(over: Partial<Limits> = {}): Limits {
  return { ...testConfig().limits, ...over };
}
