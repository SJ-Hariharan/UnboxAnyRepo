import { readManifest, isPlainObject, ownObject, ownString, countKeys, displayText } from './util.ts';
import type { DetectInput } from './util.ts';
import type { Confidence } from '../checks/types.ts';

export interface NodeFacts {
  confidence: Confidence;
  evidence: string[];
  notes: string[];
  /** Why no checks can be offered, if so. */
  blocker?: string;
  lockfile: 'package-lock.json' | 'npm-shrinkwrap.json' | null;
  hasDependencies: boolean;
  scripts: { test?: string; build?: string; lint?: string };
}

const NPM_PLACEHOLDER_TEST = /no test specified/i;

export function detectNode(input: DetectInput, present: ReadonlySet<string>): NodeFacts | null {
  if (!present.has('package.json')) return null;
  const evidence = ['package.json'];
  const notes: string[] = [];
  const base = { evidence, notes, lockfile: null, hasDependencies: false, scripts: {} } as NodeFacts;

  const m = readManifest(input, 'package.json', present);
  if (m.state === 'too_large') return { ...base, confidence: 'low', blocker: 'package.json is larger than 256 KB, so it was not parsed.' };
  if (m.state !== 'ok') return { ...base, confidence: 'low', blocker: 'package.json is not valid UTF-8.' };

  let pkg: unknown;
  try {
    pkg = JSON.parse(m.text);
  } catch {
    return { ...base, confidence: 'low', blocker: 'package.json is not valid JSON.' };
  }
  if (!isPlainObject(pkg)) return { ...base, confidence: 'low', blocker: 'package.json does not contain a JSON object.' };

  // Package manager. This version only drives npm.
  const lockfile = present.has('package-lock.json')
    ? 'package-lock.json'
    : present.has('npm-shrinkwrap.json')
      ? 'npm-shrinkwrap.json'
      : null;
  if (lockfile) evidence.push(lockfile);
  const other = ['yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock'].filter((f) => present.has(f));
  evidence.push(...other);
  const pm = ownString(pkg, 'packageManager');
  const pmName = pm ? /^(npm|yarn|pnpm|bun)@/.exec(pm)?.[1] : undefined;
  if ((pmName && pmName !== 'npm') || (other.length > 0 && lockfile === null)) {
    const which = pmName && pmName !== 'npm' ? pmName : (other[0] ?? '').replace(/[-.].*$/, '');
    return {
      ...base,
      confidence: 'medium',
      blocker: `This project uses ${which}. Only npm is supported in this version.`,
    };
  }

  const scriptsObj = ownObject(pkg, 'scripts') ?? {};
  const scripts: NodeFacts['scripts'] = {};
  const test = ownString(scriptsObj, 'test');
  if (test !== undefined && test.trim() !== '' && !NPM_PLACEHOLDER_TEST.test(test)) scripts.test = displayText(test, 300);
  const build = ownString(scriptsObj, 'build');
  if (build !== undefined && build.trim() !== '') scripts.build = displayText(build, 300);
  const lint = ownString(scriptsObj, 'lint');
  if (lint !== undefined && lint.trim() !== '') scripts.lint = displayText(lint, 300);

  const hasDependencies =
    countKeys(ownObject(pkg, 'dependencies')) +
      countKeys(ownObject(pkg, 'devDependencies')) +
      countKeys(ownObject(pkg, 'optionalDependencies')) >
    0;

  if (Object.hasOwn(pkg, 'workspaces')) notes.push('npm workspaces detected; checks run from the repository root.');
  const engines = ownObject(pkg, 'engines');
  const nodeEngine = engines ? ownString(engines, 'node') : undefined;
  if (nodeEngine) notes.push(`Declares engines.node "${displayText(nodeEngine, 40)}".`);
  if (hasDependencies && lockfile === null) {
    notes.push('No package-lock.json: dependency versions are resolved at install time.');
  }

  const confidence: Confidence = Object.keys(scripts).length > 0 ? 'high' : 'medium';
  return { ...base, confidence, lockfile, hasDependencies, scripts };
}
