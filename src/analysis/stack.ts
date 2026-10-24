/**
 * Technology stack, package managers, manifests, scripts and test tooling,
 * read from manifests only. Nothing is executed and nothing is resolved from
 * the network.
 */
import { parse as parseToml } from 'smol-toml';
import type { SourceView } from './source.ts';
import type { StackItem, PackageManagerInfo, ManifestInfo, ScriptInfo, ScriptKind, TestInfo } from './types.ts';
import { isVendored, isLockfile, baseName, isTestPath } from './paths.ts';
import { isPlainObject, displayText } from '../detect/util.ts';

export interface NodeProject {
  path: string;
  pkg: Record<string, unknown>;
  deps: Map<string, string>;
  devDeps: Map<string, string>;
  scripts: Map<string, string>;
}

export interface PythonProject {
  /** Lowercased distribution names mapped to the raw requirement text. */
  deps: Map<string, string>;
  sources: string[];
  requiresPython?: string;
  poetry: boolean;
}

export interface StackAnalysis {
  stack: StackItem[];
  packageManagers: PackageManagerInfo[];
  manifests: ManifestInfo[];
  scripts: ScriptInfo[];
  tests: TestInfo;
  node?: NodeProject;
  python?: PythonProject;
  goModule?: { module: string; goVersion?: string; requires: Map<string, string> };
  cargo?: { deps: Map<string, string>; name?: string };
}

const MANIFEST_KINDS: [RegExp, string][] = [
  [/^package\.json$/, 'npm package'],
  [/^(package-lock\.json|npm-shrinkwrap\.json)$/, 'npm lockfile'],
  [/^yarn\.lock$/, 'Yarn lockfile'],
  [/^pnpm-lock\.yaml$/, 'pnpm lockfile'],
  [/^bun\.lockb?$/, 'Bun lockfile'],
  [/^pyproject\.toml$/, 'Python project'],
  [/^requirements[A-Za-z0-9._-]*\.txt$/, 'pip requirements'],
  [/^Pipfile$/, 'Pipenv'],
  [/^Pipfile\.lock$/, 'Pipenv lockfile'],
  [/^poetry\.lock$/, 'Poetry lockfile'],
  [/^uv\.lock$/, 'uv lockfile'],
  [/^setup\.py$/, 'setuptools script'],
  [/^setup\.cfg$/, 'setuptools config'],
  [/^environment\.ya?ml$/, 'Conda environment'],
  [/^go\.mod$/, 'Go module'],
  [/^go\.sum$/, 'Go checksums'],
  [/^Cargo\.toml$/, 'Cargo manifest'],
  [/^Cargo\.lock$/, 'Cargo lockfile'],
  [/^Gemfile$/, 'Bundler'],
  [/^Gemfile\.lock$/, 'Bundler lockfile'],
  [/^composer\.json$/, 'Composer'],
  [/^composer\.lock$/, 'Composer lockfile'],
  [/^pom\.xml$/, 'Maven'],
  [/^build\.gradle(\.kts)?$/, 'Gradle'],
  [/^deno\.jsonc?$/, 'Deno'],
  [/^pubspec\.yaml$/, 'Dart/Flutter'],
  [/^mix\.exs$/, 'Elixir Mix'],
  [/^Package\.swift$/, 'Swift Package'],
  [/^[^/]+\.csproj$/, '.NET project'],
];

const NODE_STACK: Record<string, [string, StackItem['kind']]> = {
  react: ['React', 'framework'], vue: ['Vue', 'framework'], svelte: ['Svelte', 'framework'], '@angular/core': ['Angular', 'framework'],
  next: ['Next.js', 'framework'], nuxt: ['Nuxt', 'framework'], '@sveltejs/kit': ['SvelteKit', 'framework'], astro: ['Astro', 'framework'],
  gatsby: ['Gatsby', 'framework'], '@remix-run/react': ['Remix', 'framework'], 'solid-js': ['Solid', 'framework'], preact: ['Preact', 'framework'],
  express: ['Express', 'framework'], fastify: ['Fastify', 'framework'], koa: ['Koa', 'framework'], '@nestjs/core': ['NestJS', 'framework'],
  '@hapi/hapi': ['hapi', 'framework'], hono: ['Hono', 'framework'], 'socket.io': ['Socket.IO', 'library'], electron: ['Electron', 'framework'],
  vite: ['Vite', 'tool'], 'react-scripts': ['Create React App', 'tool'], webpack: ['webpack', 'tool'], parcel: ['Parcel', 'tool'],
  esbuild: ['esbuild', 'tool'], typescript: ['TypeScript', 'tool'], tailwindcss: ['Tailwind CSS', 'library'],
  prisma: ['Prisma', 'library'], '@prisma/client': ['Prisma', 'library'], mongoose: ['Mongoose (MongoDB)', 'database'],
  pg: ['PostgreSQL client', 'database'], mysql2: ['MySQL client', 'database'], mysql: ['MySQL client', 'database'],
  sqlite3: ['SQLite', 'database'], 'better-sqlite3': ['SQLite', 'database'], redis: ['Redis client', 'database'], ioredis: ['Redis client', 'database'],
  sequelize: ['Sequelize', 'library'], typeorm: ['TypeORM', 'library'], 'drizzle-orm': ['Drizzle ORM', 'library'],
  jest: ['Jest', 'tool'], vitest: ['Vitest', 'tool'], mocha: ['Mocha', 'tool'], ava: ['AVA', 'tool'], '@playwright/test': ['Playwright', 'tool'],
  cypress: ['Cypress', 'tool'], eslint: ['ESLint', 'tool'], prettier: ['Prettier', 'tool'],
};

const PY_STACK: Record<string, [string, StackItem['kind']]> = {
  flask: ['Flask', 'framework'], django: ['Django', 'framework'], fastapi: ['FastAPI', 'framework'], starlette: ['Starlette', 'framework'],
  streamlit: ['Streamlit', 'framework'], gradio: ['Gradio', 'framework'], dash: ['Dash', 'framework'], tornado: ['Tornado', 'framework'],
  aiohttp: ['aiohttp', 'framework'], sanic: ['Sanic', 'framework'], pyramid: ['Pyramid', 'framework'], quart: ['Quart', 'framework'],
  uvicorn: ['Uvicorn', 'tool'], gunicorn: ['Gunicorn', 'tool'], celery: ['Celery', 'library'], sqlalchemy: ['SQLAlchemy', 'library'],
  'psycopg2': ['PostgreSQL client', 'database'], 'psycopg2-binary': ['PostgreSQL client', 'database'], psycopg: ['PostgreSQL client', 'database'],
  pymongo: ['MongoDB client', 'database'], redis: ['Redis client', 'database'], pymysql: ['MySQL client', 'database'],
  pytest: ['pytest', 'tool'], numpy: ['NumPy', 'library'], pandas: ['pandas', 'library'], torch: ['PyTorch', 'library'],
  tensorflow: ['TensorFlow', 'library'], 'scikit-learn': ['scikit-learn', 'library'], jupyter: ['Jupyter', 'tool'], notebook: ['Jupyter', 'tool'],
  pydantic: ['Pydantic', 'library'], requests: ['Requests', 'library'], httpx: ['HTTPX', 'library'], openai: ['OpenAI SDK', 'library'],
  anthropic: ['Anthropic SDK', 'library'], langchain: ['LangChain', 'library'],
};

const GO_STACK: Record<string, string> = {
  'github.com/gin-gonic/gin': 'Gin', 'github.com/labstack/echo/v4': 'Echo', 'github.com/gofiber/fiber/v2': 'Fiber',
  'github.com/gorilla/mux': 'Gorilla Mux', 'github.com/go-chi/chi/v5': 'chi', 'github.com/spf13/cobra': 'Cobra',
  'gorm.io/gorm': 'GORM', 'google.golang.org/grpc': 'gRPC',
};

const RUST_STACK: Record<string, string> = {
  'actix-web': 'Actix Web', axum: 'Axum', rocket: 'Rocket', tokio: 'Tokio', warp: 'warp', tauri: 'Tauri', bevy: 'Bevy', clap: 'clap', diesel: 'Diesel', sqlx: 'SQLx',
};

function stringMap(obj: unknown, max = 2000): Map<string, string> {
  const out = new Map<string, string>();
  if (!isPlainObject(obj)) return out;
  for (const [k, v] of Object.entries(obj)) {
    if (out.size >= max) break;
    if (typeof v === 'string' && k.length <= 214) out.set(k, v);
  }
  return out;
}

export function classifyScript(name: string): ScriptKind {
  if (/^(pre|post)?(install|uninstall)$|^prepare$|^prepublish(Only)?$|^prepack$|^postpack$/.test(name)) return 'lifecycle';
  if (/^(start|serve|preview)(:|$)/.test(name)) return 'start';
  if (/^dev(:|$)|^develop$|^watch(:|$)/.test(name)) return 'dev';
  if (/^build(:|$)|^compile(:|$)|^dist$/.test(name)) return 'build';
  if (/^(test|e2e|coverage)(:|$)|^check$/.test(name)) return 'test';
  if (/^(lint|format|fmt|typecheck)(:|$)/.test(name)) return 'lint';
  return 'other';
}

/** "name==1.2.3 ; marker" → [name, version spec]. Lenient: for analysis only, never executed. */
export function parseRequirementLine(line: string): [string, string] | undefined {
  const t = line.replace(/\s+#.*$/, '').trim();
  if (t === '' || t.startsWith('#') || t.startsWith('-')) return undefined;
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;]*)/.exec(t);
  if (!m) return undefined;
  return [(m[1] as string).toLowerCase().replace(/_/g, '-'), (m[3] ?? '').trim()];
}

export function analyseStack(src: SourceView): StackAnalysis {
  const stack: StackItem[] = [];
  const seenStack = new Set<string>();
  const addStack = (item: StackItem) => {
    const key = `${item.kind}:${item.name}`;
    if (seenStack.has(key)) return;
    seenStack.add(key);
    stack.push(item);
  };

  // ------------------------------------------------------------- manifests
  const manifests: ManifestInfo[] = [];
  for (const f of src.files) {
    if (isVendored(f.path) || manifests.length >= 60) continue;
    const b = baseName(f.path);
    for (const [re, kind] of MANIFEST_KINDS) {
      if (re.test(b)) {
        manifests.push({ path: f.path, kind, lockfile: isLockfile(f.path) });
        break;
      }
    }
  }

  const result: StackAnalysis = {
    stack,
    packageManagers: [],
    manifests,
    scripts: [],
    tests: { frameworks: [], configFiles: [], testFiles: 0, commands: [] },
  };
  const pm = (name: string, ecosystem: string, evidence: string, lockfile?: string) =>
    result.packageManagers.push({ name, ecosystem, evidence, ...(lockfile ? { lockfile } : {}) });

  // ------------------------------------------------------------------ Node
  const pkg = src.json('package.json');
  if (pkg) {
    const node: NodeProject = {
      path: 'package.json',
      pkg,
      deps: stringMap(pkg.dependencies),
      devDeps: stringMap(pkg.devDependencies),
      scripts: stringMap(pkg.scripts, 200),
    };
    result.node = node;
    for (const [dep, version] of [...node.deps, ...node.devDeps]) {
      const hit = Object.hasOwn(NODE_STACK, dep) ? NODE_STACK[dep] : undefined;
      if (hit) addStack({ name: hit[0], kind: hit[1], ecosystem: 'npm', version: displayText(version, 40), evidence: `package.json → ${node.deps.has(dep) ? 'dependencies' : 'devDependencies'}.${dep}` });
    }
    const engines = isPlainObject(pkg.engines) ? pkg.engines : undefined;
    if (engines && typeof engines.node === 'string') addStack({ name: 'Node.js', kind: 'runtime', version: displayText(engines.node, 60), evidence: 'package.json → engines.node' });
    const declared = typeof pkg.packageManager === 'string' ? pkg.packageManager : undefined;
    if (src.has('pnpm-lock.yaml') || declared?.startsWith('pnpm@')) pm('pnpm', 'npm', declared ? `packageManager: ${displayText(declared, 40)}` : 'pnpm-lock.yaml', src.has('pnpm-lock.yaml') ? 'pnpm-lock.yaml' : undefined);
    else if (src.has('yarn.lock') || declared?.startsWith('yarn@')) pm('Yarn', 'npm', declared ? `packageManager: ${displayText(declared, 40)}` : 'yarn.lock', src.has('yarn.lock') ? 'yarn.lock' : undefined);
    else if (src.has('bun.lockb') || src.has('bun.lock')) pm('Bun', 'npm', 'bun lockfile', src.has('bun.lock') ? 'bun.lock' : 'bun.lockb');
    else if (src.has('package-lock.json') || src.has('npm-shrinkwrap.json')) pm('npm', 'npm', 'package-lock.json', src.has('package-lock.json') ? 'package-lock.json' : 'npm-shrinkwrap.json');
    else pm('npm', 'npm', 'package.json without a lockfile');
    for (const [name, command] of node.scripts) {
      result.scripts.push({ source: 'package.json', name: displayText(name, 60), command: displayText(command, 300), kind: classifyScript(name) });
    }
  }
  for (const f of ['.nvmrc', '.node-version']) {
    const t = src.text(f)?.trim();
    if (t && t.length < 40) addStack({ name: 'Node.js', kind: 'runtime', version: displayText(t, 40), evidence: f });
  }

  // ---------------------------------------------------------------- Python
  const py: PythonProject = { deps: new Map(), sources: [], poetry: false };
  for (const f of src.files) {
    if (!/^(requirements[A-Za-z0-9._-]*\.txt|requirements\/[A-Za-z0-9._-]+\.txt)$/.test(f.path)) continue;
    const t = src.text(f.path);
    if (t === undefined) continue;
    py.sources.push(f.path);
    for (const line of t.split(/\r?\n/).slice(0, 2000)) {
      const r = parseRequirementLine(line);
      if (r && !py.deps.has(r[0])) py.deps.set(r[0], r[1]);
    }
  }
  const pyproject = src.text('pyproject.toml');
  if (pyproject !== undefined) {
    py.sources.push('pyproject.toml');
    try {
      const doc = parseToml(pyproject) as Record<string, unknown>;
      const project = isPlainObject(doc.project) ? doc.project : undefined;
      const list: unknown[] = [];
      if (project) {
        if (Array.isArray(project.dependencies)) list.push(...project.dependencies);
        if (isPlainObject(project['optional-dependencies'])) for (const v of Object.values(project['optional-dependencies'])) if (Array.isArray(v)) list.push(...v);
        if (typeof project['requires-python'] === 'string') py.requiresPython = displayText(project['requires-python'], 40);
        const scripts = isPlainObject(project.scripts) ? project.scripts : undefined;
        if (scripts) for (const [k, v] of Object.entries(scripts).slice(0, 40)) if (typeof v === 'string') result.scripts.push({ source: 'pyproject.toml [project.scripts]', name: displayText(k, 60), command: displayText(v, 200), kind: 'start' });
      }
      for (const item of list.slice(0, 1000)) {
        if (typeof item !== 'string') continue;
        const r = parseRequirementLine(item);
        if (r && !py.deps.has(r[0])) py.deps.set(r[0], r[1]);
      }
      const tool = isPlainObject(doc.tool) ? doc.tool : undefined;
      const poetry = tool && isPlainObject(tool.poetry) ? tool.poetry : undefined;
      if (poetry) {
        py.poetry = true;
        const groups = isPlainObject(poetry.group) ? Object.values(poetry.group).map((g) => (isPlainObject(g) ? g.dependencies : undefined)) : [];
        for (const section of [poetry.dependencies, poetry['dev-dependencies'], ...groups.slice(0, 20)]) {
          if (!isPlainObject(section)) continue;
          for (const [k, v] of Object.entries(section).slice(0, 500)) {
            if (k.toLowerCase() === 'python') {
              if (typeof v === 'string') py.requiresPython ??= displayText(v, 40);
              continue;
            }
            py.deps.set(k.toLowerCase().replace(/_/g, '-'), typeof v === 'string' ? v : '');
          }
        }
      }
    } catch {
      /* malformed TOML is reported through compatibility notes */
    }
  }
  const pipfile = src.text('Pipfile');
  if (pipfile !== undefined) {
    py.sources.push('Pipfile');
    try {
      const doc = parseToml(pipfile) as Record<string, unknown>;
      for (const section of [doc.packages, doc['dev-packages']]) {
        if (!isPlainObject(section)) continue;
        for (const [k, v] of Object.entries(section).slice(0, 500)) py.deps.set(k.toLowerCase().replace(/_/g, '-'), typeof v === 'string' ? v : '');
      }
    } catch {
      /* reported elsewhere */
    }
  }
  for (const f of ['.python-version', 'runtime.txt']) {
    const t = src.text(f)?.trim();
    if (t && t.length < 40) py.requiresPython ??= displayText(t, 40);
  }
  if (py.sources.length > 0 || src.has('setup.py') || src.find(/^[^/]+\.py$/).length > 0) {
    if (py.sources.length > 0 || src.has('setup.py')) result.python = py;
    for (const [dep, spec] of py.deps) {
      const hit = Object.hasOwn(PY_STACK, dep) ? PY_STACK[dep] : undefined;
      if (hit) addStack({ name: hit[0], kind: hit[1], ecosystem: 'PyPI', ...(spec ? { version: displayText(spec, 40) } : {}), evidence: `Python dependency "${dep}"` });
    }
    if (py.requiresPython) addStack({ name: 'Python', kind: 'runtime', version: py.requiresPython, evidence: 'requires-python / .python-version' });
    if (src.has('poetry.lock') || py.poetry) pm('Poetry', 'PyPI', src.has('poetry.lock') ? 'poetry.lock' : '[tool.poetry] in pyproject.toml', src.has('poetry.lock') ? 'poetry.lock' : undefined);
    else if (src.has('uv.lock')) pm('uv', 'PyPI', 'uv.lock', 'uv.lock');
    else if (src.has('Pipfile')) pm('Pipenv', 'PyPI', 'Pipfile', src.has('Pipfile.lock') ? 'Pipfile.lock' : undefined);
    else if (py.sources.some((s) => s.includes('requirements'))) pm('pip', 'PyPI', py.sources.filter((s) => s.includes('requirements')).join(', '));
    else if (src.has('pyproject.toml')) pm('pip (PEP 621)', 'PyPI', 'pyproject.toml');
  }

  // -------------------------------------------------------------------- Go
  const gomod = src.text('go.mod');
  if (gomod !== undefined) {
    const module = /^module\s+(\S+)/m.exec(gomod)?.[1] ?? '';
    const goVersion = /^go\s+(\d+\.\d+(?:\.\d+)?)/m.exec(gomod)?.[1];
    const requires = new Map<string, string>();
    for (const m of gomod.matchAll(/^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}\/[^\s]+)\s+(v[0-9][^\s]*)/gim)) {
      if (requires.size < 2000) requires.set(m[1] as string, m[2] as string);
    }
    result.goModule = { module: displayText(module, 200), ...(goVersion ? { goVersion } : {}), requires };
    if (goVersion) addStack({ name: 'Go', kind: 'runtime', version: goVersion, evidence: 'go.mod go directive' });
    for (const [mod, v] of requires) {
      const hit = Object.hasOwn(GO_STACK, mod) ? GO_STACK[mod] : undefined;
      if (hit) addStack({ name: hit, kind: 'framework', ecosystem: 'Go', version: v, evidence: `go.mod require ${mod}` });
    }
    pm('Go modules', 'Go', 'go.mod', src.has('go.sum') ? 'go.sum' : undefined);
  }

  // ------------------------------------------------------------------ Rust
  const cargoText = src.text('Cargo.toml');
  if (cargoText !== undefined) {
    const deps = new Map<string, string>();
    let name: string | undefined;
    try {
      const doc = parseToml(cargoText) as Record<string, unknown>;
      const pkgSec = isPlainObject(doc.package) ? doc.package : undefined;
      if (pkgSec && typeof pkgSec.name === 'string') name = displayText(pkgSec.name, 60);
      for (const sec of [doc.dependencies, doc['dev-dependencies']]) {
        if (!isPlainObject(sec)) continue;
        for (const [k, v] of Object.entries(sec).slice(0, 500)) deps.set(k, typeof v === 'string' ? v : isPlainObject(v) && typeof v.version === 'string' ? v.version : '');
      }
    } catch {
      /* reported elsewhere */
    }
    result.cargo = { deps, ...(name ? { name } : {}) };
    for (const [d, v] of deps) {
      const hit = Object.hasOwn(RUST_STACK, d) ? RUST_STACK[d] : undefined;
      if (hit) addStack({ name: hit, kind: 'framework', ecosystem: 'crates.io', ...(v ? { version: displayText(v, 30) } : {}), evidence: `Cargo.toml dependency "${d}"` });
    }
    pm('Cargo', 'crates.io', 'Cargo.toml', src.has('Cargo.lock') ? 'Cargo.lock' : undefined);
  }

  // ---------------------------------------------------------------- Others
  if (src.has('Gemfile')) pm('Bundler', 'RubyGems', 'Gemfile', src.has('Gemfile.lock') ? 'Gemfile.lock' : undefined);
  if (src.has('composer.json')) pm('Composer', 'Packagist', 'composer.json', src.has('composer.lock') ? 'composer.lock' : undefined);
  if (src.has('pom.xml')) pm('Maven', 'Maven', 'pom.xml');
  if (src.has('build.gradle') || src.has('build.gradle.kts')) pm('Gradle', 'Maven', src.has('build.gradle') ? 'build.gradle' : 'build.gradle.kts');
  const gemfile = src.text('Gemfile');
  if (gemfile && /^\s*gem\s+['"]rails['"]/m.test(gemfile)) addStack({ name: 'Ruby on Rails', kind: 'framework', ecosystem: 'RubyGems', evidence: 'Gemfile gem "rails"' });
  const composer = src.json('composer.json');
  if (composer && isPlainObject(composer.require) && Object.hasOwn(composer.require, 'laravel/framework')) addStack({ name: 'Laravel', kind: 'framework', ecosystem: 'Packagist', evidence: 'composer.json require laravel/framework' });
  const pom = src.text('pom.xml');
  if (pom && /spring-boot/.test(pom)) addStack({ name: 'Spring Boot', kind: 'framework', ecosystem: 'Maven', evidence: 'pom.xml mentions spring-boot' });

  // Makefile targets and Procfile processes are listed, never run.
  const makefile = src.text('Makefile') ?? src.text('makefile');
  if (makefile) {
    for (const m of makefile.matchAll(/^([A-Za-z0-9][A-Za-z0-9_.-]{0,40}):(?!=)/gm)) {
      if (result.scripts.length > 300) break;
      const name = m[1] as string;
      if (name === '.PHONY') continue;
      result.scripts.push({ source: 'Makefile', name, command: `make ${name}`, kind: classifyScript(name) });
    }
  }
  const procfile = src.text('Procfile');
  if (procfile) {
    for (const line of procfile.split(/\r?\n/).slice(0, 20)) {
      const m = /^([A-Za-z0-9_-]+):\s*(.+)$/.exec(line);
      if (m) result.scripts.push({ source: 'Procfile', name: m[1] as string, command: displayText(m[2] as string, 300), kind: m[1] === 'web' ? 'start' : 'other' });
    }
  }

  // ----------------------------------------------------------------- Tests
  const tests = result.tests;
  const testConfigRe = /^(jest|vitest|playwright|cypress|karma|ava)\.config\.[a-z]+$|^\.mocharc(\.[a-z]+)?$|^pytest\.ini$|^tox\.ini$|^conftest\.py$|^noxfile\.py$|^phpunit\.xml(\.dist)?$/;
  for (const f of src.files) {
    if (isVendored(f.path)) continue;
    if (testConfigRe.test(baseName(f.path)) && f.path.split('/').length <= 2 && tests.configFiles.length < 20) tests.configFiles.push(f.path);
    if (isTestPath(f.path) || /_test\.go$/.test(f.path)) tests.testFiles++;
  }
  const fw = new Set<string>();
  for (const s of stack) if (['Jest', 'Vitest', 'Mocha', 'AVA', 'Playwright', 'Cypress', 'pytest'].includes(s.name)) fw.add(s.name);
  if (tests.configFiles.some((p) => /pytest\.ini|conftest\.py|tox\.ini/.test(p)) || (pyproject && /\[tool\.pytest/.test(pyproject))) fw.add('pytest');
  if (src.files.some((f) => /_test\.go$/.test(f.path))) fw.add('go test');
  if (cargoText !== undefined) fw.add('cargo test');
  if (result.node?.scripts.get('test')?.includes('node --test')) fw.add('node:test');
  tests.frameworks = [...fw];
  const npmTest = result.node?.scripts.get('test');
  if (npmTest && !/no test specified/.test(npmTest)) tests.commands.push({ command: 'npm test', source: `package.json scripts.test: ${displayText(npmTest, 120)}` });
  if (fw.has('pytest')) tests.commands.push({ command: 'python -m pytest', source: 'pytest configuration or dependency' });
  if (fw.has('go test')) tests.commands.push({ command: 'go test ./...', source: '*_test.go files' });
  if (fw.has('cargo test')) tests.commands.push({ command: 'cargo test', source: 'Cargo.toml' });

  return result;
}
