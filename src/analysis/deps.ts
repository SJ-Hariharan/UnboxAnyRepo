/**
 * Dependency inventory from manifests and lockfiles. Only exact versions are
 * used for vulnerability matching; ranges are listed but not matched, because
 * the installed version cannot be known without resolving them.
 */
import { parse as parseToml } from 'smol-toml';
import type { SourceView } from './source.ts';
import type { DependencyPackage, DependencySummary } from './types.ts';
import type { StackAnalysis } from './stack.ts';
import { parseYamlDoc } from './infra.ts';
import { isPlainObject } from '../detect/util.ts';

const MAX_PACKAGES = 3000;
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

  // ------------------------------------------------------------------ npm
  const npmLock = src.has('package-lock.json') ? 'package-lock.json' : src.has('npm-shrinkwrap.json') ? 'npm-shrinkwrap.json' : undefined;
  if (npmLock) {
    const lock = src.json(npmLock);
    if (!lock) notes.push(`${npmLock} could not be read (too large or not valid JSON); npm dependencies were not checked.`);
    else {
      lockfiles.push(npmLock);
      if (isPlainObject(lock.packages)) {
        for (const [key, v] of Object.entries(lock.packages)) {
          if (key === '' || !isPlainObject(v) || v.link === true) continue;
          const name = typeof v.name === 'string' ? v.name : key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
          if (typeof v.version === 'string') add({ ecosystem: 'npm', name, version: v.version, exact: true, source: npmLock });
        }
      } else if (isPlainObject(lock.dependencies)) {
        const walk = (deps: Record<string, unknown>, depth: number) => {
          if (depth > 30) return;
          for (const [name, v] of Object.entries(deps)) {
            if (!isPlainObject(v)) continue;
            if (typeof v.version === 'string' && !v.version.includes(':')) add({ ecosystem: 'npm', name, version: v.version, exact: true, source: npmLock });
            if (isPlainObject(v.dependencies)) walk(v.dependencies, depth + 1);
          }
        };
        walk(lock.dependencies, 0);
      }
    }
  }
  const yarnLock = src.text('yarn.lock');
  if (yarnLock !== undefined) {
    lockfiles.push('yarn.lock');
    // v1:   "name@^1.0.0", name@~1.1:\n  version "1.2.3"
    // berry: "name@npm:^1.0.0":\n  version: 1.2.3
    const re = /^"?((?:@[^@\s/"]+\/)?[^@\s"]+)@[^\n]*\n(?:[ \t]+[^\n]*\n)*?[ \t]+version:?\s+"?([^"\s]+)"?/gm;
    let m: RegExpExecArray | null;
    while ((m = re.exec(yarnLock)) !== null) add({ ecosystem: 'npm', name: m[1] as string, version: m[2] as string, exact: true, source: 'yarn.lock' });
  }
  const pnpmLock = src.text('pnpm-lock.yaml');
  if (pnpmLock !== undefined) {
    const { doc } = parseYamlDoc(pnpmLock);
    if (doc && isPlainObject(doc.packages)) {
      lockfiles.push('pnpm-lock.yaml');
      for (const key of Object.keys(doc.packages)) {
        // v6: "/name@1.2.3(peer@x)", v9: "name@1.2.3"
        const m = /^\/?((?:@[^@/]+\/)?[^@/(]+)@([^(]+)/.exec(key);
        if (m) add({ ecosystem: 'npm', name: m[1] as string, version: m[2] as string, exact: true, source: 'pnpm-lock.yaml' });
      }
    } else notes.push('pnpm-lock.yaml could not be parsed; npm dependencies were not checked.');
  }
  if (stack.node && !npmLock && yarnLock === undefined && pnpmLock === undefined) {
    notes.push('No npm lockfile: package.json only declares version ranges, so installed versions (and their vulnerabilities) cannot be determined.');
    for (const [name, range] of [...stack.node.deps, ...stack.node.devDeps]) {
      if (/^\d+\.\d+\.\d+$/.test(range)) add({ ecosystem: 'npm', name, version: range, exact: true, source: 'package.json (exact pin)' });
    }
  }

  // --------------------------------------------------------------- Python
  const pipLock = src.json('Pipfile.lock');
  if (pipLock) {
    lockfiles.push('Pipfile.lock');
    for (const section of [pipLock.default, pipLock.develop]) {
      if (!isPlainObject(section)) continue;
      for (const [name, v] of Object.entries(section)) {
        if (isPlainObject(v) && typeof v.version === 'string' && v.version.startsWith('==')) add({ ecosystem: 'PyPI', name, version: v.version.slice(2), exact: true, source: 'Pipfile.lock' });
      }
    }
  }
  for (const lockName of ['poetry.lock', 'uv.lock']) {
    const t = src.text(lockName);
    if (t === undefined) continue;
    try {
      const doc = parseToml(t) as Record<string, unknown>;
      const list = Array.isArray(doc.package) ? doc.package : [];
      lockfiles.push(lockName);
      for (const p of list) {
        if (!isPlainObject(p) || typeof p.name !== 'string' || typeof p.version !== 'string') continue;
        // uv lists the project itself with an editable/virtual source; skip local entries.
        if (isPlainObject(p.source) && (p.source.editable !== undefined || p.source.virtual !== undefined)) continue;
        add({ ecosystem: 'PyPI', name: p.name, version: p.version, exact: true, source: lockName });
      }
    } catch {
      notes.push(`${lockName} could not be parsed; Python dependencies from it were not checked.`);
    }
  }
  if (stack.python) {
    let ranged = 0;
    for (const [name, spec] of stack.python.deps) {
      const m = /^===?\s*([0-9][0-9A-Za-z.+!_-]*)$/.exec(spec.trim());
      if (m) add({ ecosystem: 'PyPI', name, version: m[1] as string, exact: true, source: stack.python.sources.join(', ') || 'Python manifest' });
      else ranged++;
    }
    if (ranged > 0 && !lockfiles.some((l) => /Pipfile|poetry|uv/.test(l))) {
      notes.push(`${ranged} Python dependenc${ranged === 1 ? 'y is' : 'ies are'} not pinned with ==, so the installed version cannot be determined and was not checked for vulnerabilities.`);
    }
  }

  // ------------------------------------------------------------------- Go
  if (stack.goModule) {
    for (const [mod, v] of stack.goModule.requires) add({ ecosystem: 'Go', name: mod, version: v.replace(/^v/, '').replace(/\+incompatible$/, ''), exact: true, source: 'go.mod' });
    if (stack.goModule.requires.size > 0) lockfiles.push('go.mod');
  }

  // ----------------------------------------------------------------- Rust
  const cargoLock = src.text('Cargo.lock');
  if (cargoLock !== undefined) {
    try {
      const doc = parseToml(cargoLock) as Record<string, unknown>;
      lockfiles.push('Cargo.lock');
      for (const p of Array.isArray(doc.package) ? doc.package : []) {
        // Packages without a source are workspace members, not downloaded crates.
        if (isPlainObject(p) && typeof p.name === 'string' && typeof p.version === 'string' && typeof p.source === 'string') {
          add({ ecosystem: 'crates.io', name: p.name, version: p.version, exact: true, source: 'Cargo.lock' });
        }
      }
    } catch {
      notes.push('Cargo.lock could not be parsed; Rust dependencies were not checked.');
    }
  } else if (stack.cargo) {
    notes.push('No Cargo.lock: crate versions are not fixed, so they were not checked for vulnerabilities.');
  }

  if (truncated) notes.push(`More than ${MAX_PACKAGES} packages: only the first ${MAX_PACKAGES} were inventoried.`);
  const packages = [...pkgs.values()];
  const byEcosystem: Record<string, number> = {};
  for (const p of packages) byEcosystem[p.ecosystem] = (byEcosystem[p.ecosystem] ?? 0) + 1;
  return { packages, byEcosystem, lockfiles: [...new Set(lockfiles)], notes, truncated };
}
