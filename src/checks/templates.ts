/**
 * Check templates: the ONLY place commands are defined.
 *
 * Every argv below is a constant chosen by this file. Values that come from
 * detection are booleans or enums selected from fixed sets; the single
 * exception is Python requirement specifiers, which are passed as individual
 * argv elements after strict validation (see detect/requirements.ts).
 *
 * Nothing here ever goes through a shell.
 */
import type { CheckOption, StepPlan } from './types.ts';
import type { NodeFacts } from '../detect/node.ts';
import type { PythonFacts } from '../detect/python.ts';
import type { GoFacts } from '../detect/go.ts';
import type { RustFacts } from '../detect/rust.ts';
import { isSafeSpec } from '../detect/requirements.ts';

/** Workspace layout inside the sandbox (created by the sanitized archive). */
export const WORK = {
  root: '/work',
  src: '/work/src',
  deps: '/work/.deps',
  home: '/work/.home',
  tmp: '/work/.home/tmp',
} as const;

const COMMON_ENV: Record<string, string> = {
  HOME: WORK.home,
  TMPDIR: WORK.tmp,
  CI: 'true',
  NO_COLOR: '1',
  LANG: 'C.UTF-8',
};

const NPM_REGISTRY = 'https://registry.npmjs.org/';
const PYPI_INDEX = 'https://pypi.org/simple';
export const PYTEST_SPEC = 'pytest<9';

const EXECUTES_REPO_CODE = 'Runs code from this repository at the pinned commit inside the sandbox.';

// ---------------------------------------------------------------- Node

const NODE_ENV_BASE: Record<string, string> = {
  ...COMMON_ENV,
  npm_config_cache: `${WORK.home}/.npm`,
  npm_config_update_notifier: 'false',
  npm_config_fund: 'false',
  npm_config_audit: 'false',
};

function nodeInstall(f: NodeFacts): StepPlan[] {
  if (!f.hasDependencies) return [];
  const common = ['--ignore-scripts', '--no-audit', '--no-fund', '--include=dev', `--registry=${NPM_REGISTRY}`];
  const argv = f.lockfile ? ['npm', 'ci', ...common] : ['npm', 'install', '--no-package-lock', ...common];
  return [
    {
      kind: 'install',
      title: f.lockfile ? `Install dependencies from ${f.lockfile} (lifecycle scripts disabled)` : 'Install dependencies (lifecycle scripts disabled)',
      argv,
      env: NODE_ENV_BASE,
      network: 'registry-proxy',
    },
  ];
}

export function nodeChecks(f: NodeFacts): CheckOption[] {
  const defs = [
    { id: 'node.npm-test', script: 'test', title: 'npm test', argv: ['npm', 'test'], summary: 'Runs the test script from package.json.' },
    { id: 'node.npm-build', script: 'build', title: 'npm run build', argv: ['npm', 'run', 'build'], summary: 'Runs the build script from package.json.' },
    { id: 'node.npm-lint', script: 'lint', title: 'npm run lint', argv: ['npm', 'run', 'lint'], summary: 'Runs the lint script from package.json.' },
  ] as const;
  return defs.map((d) => {
    const scriptText = f.scripts[d.script];
    const install = nodeInstall(f);
    const reason = f.blocker ?? (scriptText === undefined ? `package.json has no "${d.script}" script.` : undefined);
    return {
      id: d.id,
      ecosystem: 'node',
      title: d.title,
      summary: d.summary,
      steps: [
        ...install,
        { kind: 'check', title: d.title, argv: [...d.argv], env: { ...NODE_ENV_BASE, npm_config_offline: 'true' }, network: 'none' },
      ],
      installsDependencies: install.length > 0,
      executes: `${EXECUTES_REPO_CODE} npm runs the "${d.script}" script (and any matching pre/post scripts) defined by the repository.`,
      repoScripts: scriptText !== undefined ? [{ source: `package.json → scripts.${d.script}`, text: scriptText }] : [],
      notes: [...f.notes],
      available: reason === undefined,
      ...(reason !== undefined ? { unavailableReason: reason } : {}),
    } satisfies CheckOption;
  });
}

// ---------------------------------------------------------------- Python

function pythonEnv(f: PythonFacts): Record<string, string> {
  const paths = [`${WORK.deps}/python`];
  if (f.srcLayout) paths.push(`${WORK.src}/src`);
  return {
    ...COMMON_ENV,
    PYTHONPATH: paths.join(':'),
    PYTHONDONTWRITEBYTECODE: '1',
    PYTHONNOUSERSITE: '1',
    PIP_CONFIG_FILE: '/dev/null',
    PIP_NO_INPUT: '1',
    PIP_DISABLE_PIP_VERSION_CHECK: '1',
  };
}

function pythonInstall(f: PythonFacts, needPytest: boolean): StepPlan[] {
  const specs = f.specs.filter(isSafeSpec); // defense in depth: detection already rejected anything else
  const extra = needPytest && !specs.some((s) => /^pytest(?![A-Za-z0-9._-])/i.test(s)) ? [PYTEST_SPEC] : [];
  const all = [...extra, ...specs];
  if (all.length === 0) return [];
  return [
    {
      kind: 'install',
      title: 'Install pre-built wheels only (no source builds, no setup.py)',
      argv: [
        'python', '-m', 'pip', 'install', '--no-input', '--disable-pip-version-check', '--no-cache-dir',
        '--only-binary=:all:', '--index-url', PYPI_INDEX, '--target', `${WORK.deps}/python`, ...all,
      ],
      env: pythonEnv(f),
      network: 'registry-proxy',
    },
  ];
}

export function pythonChecks(f: PythonFacts): CheckOption[] {
  const out: CheckOption[] = [];
  const noTests = f.hasTests ? undefined : 'No test files (test_*.py or *_test.py) were found.';
  if (f.usesPytest || !f.hasTests) {
    const install = pythonInstall(f, true);
    const reason = f.blocker ?? noTests;
    out.push({
      id: 'python.pytest',
      ecosystem: 'python',
      title: 'pytest',
      summary: 'Installs declared dependencies as wheels, then runs pytest.',
      steps: [
        ...install,
        { kind: 'check', title: 'pytest', argv: ['python', '-m', 'pytest', '-q', '-p', 'no:cacheprovider'], env: pythonEnv(f), network: 'none' },
      ],
      installsDependencies: install.length > 0,
      executes: `${EXECUTES_REPO_CODE} pytest imports test modules and conftest.py files from the repository.`,
      repoScripts: [],
      notes: [...f.notes, 'Packages without a pre-built wheel cannot be installed.'],
      available: reason === undefined,
      ...(reason !== undefined ? { unavailableReason: reason } : {}),
    });
  }
  if (!f.usesPytest && f.hasTests) {
    const install = pythonInstall(f, false);
    const reason = f.blocker;
    const argv = ['python', '-m', 'unittest', 'discover', '-v'];
    if (f.unittestStart !== '.') argv.push('-s', f.unittestStart, '-t', '.');
    out.push({
      id: 'python.unittest',
      ecosystem: 'python',
      title: 'unittest discover',
      summary: 'Runs the standard-library unittest discovery.',
      steps: [...install, { kind: 'check', title: 'unittest', argv, env: pythonEnv(f), network: 'none' }],
      installsDependencies: install.length > 0,
      executes: `${EXECUTES_REPO_CODE} unittest imports the repository's test modules.`,
      repoScripts: [],
      notes: [...f.notes],
      available: reason === undefined,
      ...(reason !== undefined ? { unavailableReason: reason } : {}),
    });
  }
  return out;
}

// ---------------------------------------------------------------- Go

function goEnv(f: GoFacts, phase: 'install' | 'check'): Record<string, string> {
  return {
    ...COMMON_ENV,
    GOPATH: `${WORK.deps}/go`,
    GOMODCACHE: `${WORK.deps}/go/pkg/mod`,
    GOCACHE: `${WORK.home}/.cache/go-build`,
    GOTMPDIR: WORK.tmp,
    GOTOOLCHAIN: 'local',
    GOWORK: 'off',
    GOFLAGS: f.vendored ? '-mod=vendor -buildvcs=false' : '-mod=readonly -buildvcs=false',
    GOPROXY: phase === 'install' ? 'https://proxy.golang.org' : 'off',
    GOSUMDB: phase === 'install' ? 'sum.golang.org' : 'off',
  };
}

export function goChecks(f: GoFacts, goImage: string): CheckOption[] {
  const needsDownload = f.requireCount > 0 && !f.vendored;
  const install: StepPlan[] = needsDownload
    ? [{ kind: 'install', title: 'Download modules listed in go.mod', argv: ['go', 'mod', 'download'], env: goEnv(f, 'install'), network: 'registry-proxy' }]
    : [];
  const notes = [...f.notes];
  const imageVersion = /golang:(\d+\.\d+)/.exec(goImage)?.[1];
  if (f.goVersion && imageVersion && compareMinor(f.goVersion, imageVersion) > 0) {
    notes.push(`go.mod asks for Go ${f.goVersion}; the sandbox image provides Go ${imageVersion}, and toolchain downloads are disabled.`);
  }
  const defs = [
    { id: 'go.test', title: 'go test ./...', argv: ['go', 'test', './...'], summary: 'Builds and runs all package tests.', needTests: true },
    { id: 'go.vet', title: 'go vet ./...', argv: ['go', 'vet', './...'], summary: 'Runs the standard Go static checks.', needTests: false },
    { id: 'go.build', title: 'go build ./...', argv: ['go', 'build', './...'], summary: 'Compiles all packages.', needTests: false },
  ] as const;
  return defs.map((d) => {
    const reason = f.blocker ?? (d.needTests && !f.hasTests ? 'No *_test.go files were found.' : undefined);
    return {
      id: d.id,
      ecosystem: 'go',
      title: d.title,
      summary: d.summary,
      steps: [...install, { kind: 'check', title: d.title, argv: [...d.argv], env: goEnv(f, 'check'), network: 'none' }],
      installsDependencies: install.length > 0,
      executes:
        d.id === 'go.test'
          ? `${EXECUTES_REPO_CODE} Test binaries built from the repository are executed.`
          : 'Compiles repository code inside the sandbox; Go builds do not normally execute it, but the toolchain processes untrusted input.',
      repoScripts: [],
      notes,
      available: reason === undefined,
      ...(reason !== undefined ? { unavailableReason: reason } : {}),
    } satisfies CheckOption;
  });
}

function compareMinor(a: string, b: string): number {
  const [a1 = 0, a2 = 0] = a.split('.').map(Number);
  const [b1 = 0, b2 = 0] = b.split('.').map(Number);
  return a1 !== b1 ? a1 - b1 : a2 - b2;
}

// ---------------------------------------------------------------- Rust

function rustEnv(phase: 'install' | 'check'): Record<string, string> {
  return {
    ...COMMON_ENV,
    CARGO_HOME: `${WORK.deps}/cargo`,
    CARGO_TARGET_DIR: `${WORK.home}/target`,
    CARGO_TERM_COLOR: 'never',
    CARGO_INCREMENTAL: '0',
    CARGO_NET_OFFLINE: phase === 'check' ? 'true' : 'false',
  };
}

export function rustChecks(f: RustFacts): CheckOption[] {
  const locked = f.locked ? ['--locked'] : [];
  const install: StepPlan[] =
    f.remoteDependencyCount > 0
      ? [{ kind: 'install', title: 'Fetch crates (no build scripts run during fetch)', argv: ['cargo', 'fetch', ...locked], env: rustEnv('install'), network: 'registry-proxy' }]
      : [];
  const defs = [
    { id: 'rust.cargo-test', title: 'cargo test', argv: ['cargo', 'test', '--offline', ...locked], summary: 'Builds and runs the crate tests.' },
    { id: 'rust.cargo-build', title: 'cargo build', argv: ['cargo', 'build', '--offline', ...locked], summary: 'Compiles the crate.' },
  ] as const;
  return defs.map((d) => {
    const reason = f.blocker;
    return {
      id: d.id,
      ecosystem: 'rust',
      title: d.title,
      summary: d.summary,
      steps: [...install, { kind: 'check', title: d.title, argv: [...d.argv], env: rustEnv('check'), network: 'none' }],
      installsDependencies: install.length > 0,
      executes: `${EXECUTES_REPO_CODE} Build scripts (build.rs) and procedural macros run at compile time${d.id === 'rust.cargo-test' ? ', then the test binaries run' : ''}.`,
      repoScripts: [],
      notes: [...f.notes],
      available: reason === undefined,
      ...(reason !== undefined ? { unavailableReason: reason } : {}),
    } satisfies CheckOption;
  });
}
