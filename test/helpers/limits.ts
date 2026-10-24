import { loadConfig } from '../../src/config.ts';
import type { Config, Limits } from '../../src/config.ts';

export function testConfig(env: Record<string, string> = {}): Config {
  return loadConfig({ UNBOX_GITHUB_SOURCE: 'fixtures', UNBOX_SCANNERS: 'off', ...env });
}

export function testLimits(over: Partial<Limits> = {}): Limits {
  return { ...testConfig().limits, ...over };
}
