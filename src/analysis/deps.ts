/**
 * Dependency inventory from manifests and lockfiles. Only exact versions are
 * used for vulnerability matching; ranges are listed but not matched, because
 * the installed version cannot be known without resolving them.
 *
 * Lockfiles are read at the repository root and in subdirectories (monorepos),
 * except vendored code and test fixtures, up to MAX_LOCKFILES files.
 */
import { parse as parseToml } from 'smol-toml';
import type { SourceView } from './source.ts';
import type { DependencyPackage, DependencySummary } from './types.ts';
import { baseName, isVendored } from './paths.ts';
import type { StackAnalysis } from './stack.ts';
import { parseYamlDoc } from './infra.ts';
import { isPlainObject } from '../detect/util.ts';

const MAX_PACKAGES = 3000;
const MAX_LOCKFILES = 40;
/** Test fixtures often pin old, vulnerable versions on purpose; they are not the project's dependencies. */
const FIXTURE_DIR_RE = /(^|\/)(fixtures?|__fixtures__|testdata|test-data|__tests__\/data)\//i;
const NAME_RE = /^[@A-Za-z0-9][A-Za-z0-9@/._~+-]{0,213}$/;
const VERSION_RE = /^[0-9A-Za-z][0-9A-Za-z.+_~-]{0,63}$/;

export function analyseDependencies(src: SourceView, stack: StackAnalysis): DependencySummary {
  const pkgs = new Map<string, DependencyPackage>();
  const lockfiles: string[] = [];
  const notes: string[] = [];
  let truncated = false;
  const add = (p: DependencyPackage) => {
    if (!NAME_RE.test(p.name) || !VERSION_RE.test(p.version)) return;
    const key = `${p.ecosystem}|${p.name.toLowerCase()}|${p.version}`;
    if (pkgs.has(key)) return;
    if (pkgs.size >= MAX_PACKAGES) {
      truncated = true;
      return;
    }
    pkgs.set(key, p);
  };
  const ctx: Ctx = { src, add, lockfiles, notes };

  // Lockfiles: the root first, then subdirectories, shallowest first.
  const candidates = src.files
    .map((f) => f.path)
    .filter((p) => LOCKFILE_PARSERS[baseName(p)] !== undefined && !isVendored(p));
  const fixtures = candidates.filter((p) => FIXTURE_DIR_RE.test(p));
  const chosen = candidates
    .filter((p) => !FIXTURE_DIR_RE.test(p))
    .sort((a, b) => a.split('/').length - b.split('/').length || a.localeCompare(b));
  if (chosen.length > MAX_LOCKFILES) notes.push(`${chosen.length} lockfiles found; only the ${MAX_LOCKFILES} closest to the root were read.`);
  for (const path of chosen.slice(0, MAX_LOCKFILES)) (LOCKFILE_PARSERS[baseName(path)] as Parser)(ctx, path);
  if (fixtures.length > 0) notes.push(`${fixtures.length} lockfile${fixtures.length === 1 ? ' in test fixtures was' : 's in test fixtures were'} not checked; they are usually test data, not the project's dependencies.`);

  const rootHas = (...names: string[]) => names.some((n) => src.has(n));
  if (stack.node && !rootHas('package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock')) {
    notes.push(
      src.has('bun.lockb')
        ? 'Only a binary bun.lockb lockfile: it cannot be read without running Bun, so installed versions were not checked. Bun 1.2+ writes a text bun.lock.'
        : 'No npm lockfile at the root: package.json only declares version ranges, so installed versions (and their vulnerabilities) cannot be determined.',
    );
    for (const [name, range] of [...stack.node.deps, ...stack.node.devDeps]) {
      if (/^\d+\.\d+\.\d+$/.test(range)) add({ ecosystem: 'npm', name, version: range, exact: true, source: 'package.json (exact pin)' });
    }
  }

  // --------------------------------------------------------------- Python
  if (stack.python) {
    let ranged = 0;
    for (const [name, spec] of stack.python.deps) {
      const m = /^===?\s*([0-9][0-9A-Za-z.+!_-]*)$/.exec(spec.trim());
      if (m) add({ ecosystem: 'PyPI', name, version: m[1] as string, exact: true, source: stack.python.sources.join(', ') || 'Python manifest' });
      else ranged++;
    }
    if (ranged > 0 && !rootHas('Pipfile.lock', 'poetry.lock', 'uv.lock')) {
      notes.push(`${ranged} Python dependenc${ranged === 1 ? 'y is' : 'ies are'} not pinned with ==, so the installed version cannot be determined and was not checked for vulnerabilities.`);
    }
  }

  // ------------------------------------------------------------------- Go
  if (stack.goModule) {
    for (const [mod, v] of stack.goModule.requires) add({ ecosystem: 'Go', name: mod, version: v.replace(/^v/, '').replace(/\+incompatible$/, ''), exact: true, source: 'go.mod' });
    if (stack.goModule.requires.size > 0) lockfiles.push('go.mod');
  }

  if (stack.cargo && !src.has('Cargo.lock')) notes.push('No Cargo.lock: crate versions are not fixed, so they were not checked for vulnerabilities.');
  if (src.has('Gemfile') && !src.has('Gemfile.lock')) notes.push('No Gemfile.lock: gem versions are not fixed, so they were not checked for vulnerabilities.');
  if (src.has('composer.json') && !src.has('composer.lock')) notes.push('No composer.lock: PHP package versions are not fixed, so they were not checked for vulnerabilities.');
  if (src.has('pubspec.yaml') && !src.has('pubspec.lock')) notes.push('No pubspec.lock: Dart package versions are not fixed, so they were not checked for vulnerabilities.');
  if (src.find(/(^|\/)[^/]+\.(csproj|fsproj|vbproj)$/).length > 0 && !src.find(/(^|\/)packages\.lock\.json$/).length) {
    notes.push('.NET project without packages.lock.json (enable RestorePackagesWithLockFile): NuGet versions were not checked for vulnerabilities.');
  }

  if (truncated) notes.push(`More than ${MAX_PACKAGES} packages: only the first ${MAX_PACKAGES} were inventoried.`);
  const packages = [...pkgs.values()];
  const byEcosystem: Record<string, number> = {};
  for (const p of packages) byEcosystem[p.ecosystem] = (byEcosystem[p.ecosystem] ?? 0) + 1;
  return { packages, byEcosystem, lockfiles: [...new Set(lockfiles)], notes, truncated };
}

interface Ctx {
  src: SourceView;
  add: (p: DependencyPackage) => void;
  lockfiles: string[];
  notes: string[];
}
type Parser = (ctx: Ctx, path: string) => void;

function npmLock({ src, add, lockfiles, notes }: Ctx, path: string): void {
  const lock = src.json(path);
  if (!lock) {
    notes.push(`${path} could not be read (too large or not valid JSON); npm dependencies from it were not checked.`);
    return;
  }
  lockfiles.push(path);
  if (isPlainObject(lock.packages)) {
    for (const [key, v] of Object.entries(lock.packages)) {
      if (key === '' || !isPlainObject(v) || v.link === true) continue;
      // Workspace members appear without node_modules/ in their key; they are not downloaded.
      if (!key.includes('node_modules/')) continue;
      const name = typeof v.name === 'string' ? v.name : key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      if (typeof v.version === 'string') add({ ecosystem: 'npm', name, version: v.version, exact: true, source: path });
    }
  } else if (isPlainObject(lock.dependencies)) {
    const walk = (deps: Record<string, unknown>, depth: number) => {
      if (depth > 30) return;
      for (const [name, v] of Object.entries(deps)) {
        if (!isPlainObject(v)) continue;
        if (typeof v.version === 'string' && !v.version.includes(':')) add({ ecosystem: 'npm', name, version: v.version, exact: true, source: path });
        if (isPlainObject(v.dependencies)) walk(v.dependencies, depth + 1);
      }
    };
    walk(lock.dependencies, 0);
  }
}

function yarnLock({ src, add, lockfiles }: Ctx, path: string): void {
  const t = src.text(path);
  if (t === undefined) return;
  lockfiles.push(path);
  // v1:   "name@^1.0.0", name@~1.1:\n  version "1.2.3"
  // berry: "name@npm:^1.0.0":\n  version: 1.2.3
  const re = /^"?((?:@[^@\s/"]+\/)?[^@\s"]+)@[^\n]*\n(?:[ \t]+[^\n]*\n)*?[ \t]+version:?\s+"?([^"\s]+)"?/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(t)) !== null) add({ ecosystem: 'npm', name: m[1] as string, version: m[2] as string, exact: true, source: path });
}

function pnpmLock({ src, add, lockfiles, notes }: Ctx, path: string): void {
  const t = src.text(path);
  if (t === undefined) return;
  const { doc } = parseYamlDoc(t);
  if (!doc || !isPlainObject(doc.packages)) {
    notes.push(`${path} could not be parsed; npm dependencies from it were not checked.`);
    return;
  }
  lockfiles.push(path);
  for (const key of Object.keys(doc.packages)) {
    // v6: "/name@1.2.3(peer@x)", v9: "name@1.2.3"
    const m = /^\/?((?:@[^@/]+\/)?[^@/(]+)@([^(]+)/.exec(key);
    if (m) add({ ecosystem: 'npm', name: m[1] as string, version: m[2] as string, exact: true, source: path });
  }
}

/** Bun's text lockfile (bun.lock, JSON with trailing commas): "key": ["name@version", …]. */
function bunLock({ src, add, lockfiles }: Ctx, path: string): void {
  const t = src.text(path);
  if (t === undefined) return;
  const at = t.indexOf('"packages"');
  if (at === -1) return;
  lockfiles.push(path);
  const re = /^\s*"[^"\n]{1,240}":\s*\[\s*"((?:@[^@"/\s]+\/)?[^@"\s]+)@([^"\s]+)"/gm;
  re.lastIndex = at;
  let m: RegExpExecArray | null;
  // Versions such as workspace:, github:, file: or npm:alias contain ':' and are rejected by VERSION_RE.
  while ((m = re.exec(t)) !== null) add({ ecosystem: 'npm', name: m[1] as string, version: m[2] as string, exact: true, source: path });
}

function pipfileLock({ src, add, lockfiles }: Ctx, path: string): void {
  const lock = src.json(path);
  if (!lock) return;
  lockfiles.push(path);
  for (const section of [lock.default, lock.develop]) {
    if (!isPlainObject(section)) continue;
    for (const [name, v] of Object.entries(section)) {
      if (isPlainObject(v) && typeof v.version === 'string' && v.version.startsWith('==')) add({ ecosystem: 'PyPI', name, version: v.version.slice(2), exact: true, source: path });
    }
  }
}

function tomlPackages(ecosystem: 'PyPI' | 'crates.io'): Parser {
  return ({ src, add, lockfiles, notes }, path) => {
    const t = src.text(path);
    if (t === undefined) return;
    try {
      const doc = parseToml(t) as Record<string, unknown>;
      lockfiles.push(path);
      for (const p of Array.isArray(doc.package) ? doc.package : []) {
        if (!isPlainObject(p) || typeof p.name !== 'string' || typeof p.version !== 'string') continue;
        if (ecosystem === 'crates.io') {
          // Packages without a source are workspace members, not downloaded crates.
          if (typeof p.source !== 'string') continue;
        } else if (isPlainObject(p.source) && (p.source.editable !== undefined || p.source.virtual !== undefined)) {
          // uv lists the project itself with an editable/virtual source; skip local entries.
          continue;
        }
        add({ ecosystem, name: p.name, version: p.version, exact: true, source: path });
      }
    } catch {
      notes.push(`${path} could not be parsed; dependencies from it were not checked.`);
    }
  };
}

/** Bundler: gems under the GEM section's "specs:" at four spaces of indentation. GIT and PATH gems are not from RubyGems. */
function gemfileLock({ src, add, lockfiles }: Ctx, path: string): void {
  const t = src.text(path);
  if (t === undefined) return;
  lockfiles.push(path);
  let section = '';
  for (const line of t.split(/\r?\n/)) {
    if (/^[A-Z]/.test(line)) {
      section = line.trim();
      continue;
    }
    if (section !== 'GEM') continue;
    const m = /^ {4}([A-Za-z0-9][A-Za-z0-9_.-]*) \(([^)\s]+)\)$/.exec(line);
    if (!m) continue;
    // "1.16.0-x86_64-linux": the platform follows the first "-" (RubyGems prereleases use dots).
    add({ ecosystem: 'RubyGems', name: m[1] as string, version: (m[2] as string).split('-')[0] as string, exact: true, source: path });
  }
}

function composerLock({ src, add, lockfiles, notes }: Ctx, path: string): void {
  const lock = src.json(path);
  if (!lock) {
    notes.push(`${path} could not be read; PHP dependencies from it were not checked.`);
    return;
  }
  lockfiles.push(path);
  for (const list of [lock.packages, lock['packages-dev']]) {
    if (!Array.isArray(list)) continue;
    for (const p of list) {
      if (!isPlainObject(p) || typeof p.name !== 'string' || typeof p.version !== 'string') continue;
      // Branch checkouts ("dev-main", "2.x-dev") are not releases.
      if (/^dev-|-dev$/.test(p.version)) continue;
      add({ ecosystem: 'Packagist', name: p.name, version: p.version.replace(/^v(?=\d)/, ''), exact: true, source: path });
    }
  }
}

function nugetLock({ src, add, lockfiles }: Ctx, path: string): void {
  const lock = src.json(path);
  if (!lock || !isPlainObject(lock.dependencies)) return;
  lockfiles.push(path);
  for (const framework of Object.values(lock.dependencies)) {
    if (!isPlainObject(framework)) continue;
    for (const [name, v] of Object.entries(framework)) {
      if (isPlainObject(v) && typeof v.resolved === 'string' && v.type !== 'Project') add({ ecosystem: 'NuGet', name, version: v.resolved, exact: true, source: path });
    }
  }
}

function pubspecLock({ src, add, lockfiles, notes }: Ctx, path: string): void {
  const t = src.text(path);
  if (t === undefined) return;
  const { doc } = parseYamlDoc(t);
  if (!doc || !isPlainObject(doc.packages)) {
    notes.push(`${path} could not be parsed; Dart dependencies from it were not checked.`);
    return;
  }
  lockfiles.push(path);
  for (const [name, v] of Object.entries(doc.packages)) {
    if (isPlainObject(v) && v.source === 'hosted' && typeof v.version === 'string') add({ ecosystem: 'Pub', name, version: v.version, exact: true, source: path });
  }
}

const LOCKFILE_PARSERS: Record<string, Parser> = {
  'package-lock.json': npmLock,
  'npm-shrinkwrap.json': npmLock,
  'yarn.lock': yarnLock,
  'pnpm-lock.yaml': pnpmLock,
  'bun.lock': bunLock,
  'Pipfile.lock': pipfileLock,
  'poetry.lock': tomlPackages('PyPI'),
  'uv.lock': tomlPackages('PyPI'),
  'Cargo.lock': tomlPackages('crates.io'),
  'Gemfile.lock': gemfileLock,
  'composer.lock': composerLock,
  'packages.lock.json': nugetLock,
  'pubspec.lock': pubspecLock,
};
