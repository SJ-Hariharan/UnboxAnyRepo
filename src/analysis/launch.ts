/**
 * Launch planning: what kind of project this is, what it needs, and the
 * commands a developer would run locally. Commands are generated from fixed
 * templates and the project's own manifest entries, never copied from README
 * files. Nothing here is executed by this server.
 */
import type { SourceView } from './source.ts';
import type { StackAnalysis } from './stack.ts';
import type { InfraAnalysis } from './infra.ts';
import type { LaunchPlan, LaunchStep, ProjectKind, PreviewPlan, CompatibilityNote, EnvVarInfo } from './types.ts';
import { isVendored } from './paths.ts';

const DB_IMAGES: [RegExp, string][] = [
  [/(^|\/)postgres|postgis|timescale/i, 'PostgreSQL'],
  [/(^|\/)(mysql|mariadb)/i, 'MySQL/MariaDB'],
  [/(^|\/)(redis|valkey)/i, 'Redis'],
  [/(^|\/)mongo/i, 'MongoDB'],
  [/(^|\/)rabbitmq/i, 'RabbitMQ'],
  [/elasticsearch|opensearch/i, 'Elasticsearch/OpenSearch'],
  [/(^|\/)(kafka|redpanda)/i, 'Kafka'],
  [/(^|\/)minio/i, 'MinIO (S3-compatible storage)'],
  [/(^|\/)memcached/i, 'Memcached'],
];
const DB_ENV: [RegExp, string][] = [
  [/^(DATABASE_URL|POSTGRES_|PG(HOST|DATABASE|USER|PASSWORD)|DB_HOST)/, 'A SQL database'],
  [/^(REDIS_URL|REDIS_HOST)/, 'Redis'],
  [/^(MONGO(DB)?_(URI|URL)|MONGO_HOST)/, 'MongoDB'],
  [/^(AMQP_URL|RABBITMQ_)/, 'RabbitMQ'],
  [/^(S3_|AWS_S3_|MINIO_)/, 'S3-compatible object storage'],
  [/^(OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|HF_TOKEN|HUGGINGFACE)/, 'An external AI API account'],
  [/^(STRIPE_)/, 'A Stripe account'],
  [/^(SUPABASE_|FIREBASE_)/, 'A Supabase/Firebase project'],
];
const NATIVE_NODE = ['bcrypt', 'sharp', 'canvas', 'sqlite3', 'better-sqlite3', 'node-sass', 'argon2', 'node-gyp', 'grpc', 'zeromq', 'serialport', 'cpu-features'];
const NATIVE_PY = ['psycopg2', 'mysqlclient', 'pycairo', 'pygobject', 'python-ldap', 'pyaudio', 'dlib', 'gdal', 'uwsgi'];

function shq(s: string): string {
  return /^[A-Za-z0-9_./:=@+-]+$/.test(s) ? s : `'${s.replace(/'/g, "'\\''")}'`;
}

function addPort(list: { port: number; source: string }[], port: number, source: string) {
  if (!Number.isInteger(port) || port < 1 || port > 65535 || list.some((p) => p.port === port) || list.length >= 8) return;
  list.push({ port, source });
}

function majorOf(range: string): number | undefined {
  const m = /(\d+)/.exec(range);
  return m ? Number(m[1]) : undefined;
}

export interface LaunchInput {
  src: SourceView;
  stack: StackAnalysis;
  infra: InfraAnalysis;
  env: { vars: EnvVarInfo[]; exampleFiles: string[]; committedEnvFiles: string[] };
  repo: { fullName: string; htmlUrl: string; name: string };
  commitSha: string;
  skippedSymlinks: number;
  /** Git LFS pointers found in the snapshot. */
  lfs?: { pointerCount: number; pointerBytes: number };
}

export function planLaunch(input: LaunchInput): { plan: LaunchPlan; compatibility: CompatibilityNote[] } {
  const { src, stack, infra, env } = input;
  const node = stack.node;
  const allNode = new Map([...(node?.deps ?? []), ...(node?.devDeps ?? [])]);
  const hasNode = (d: string) => allNode.has(d);
  const py = stack.python;
  const hasPy = (d: string) => py?.deps.has(d) ?? false;
  const kinds: ProjectKind[] = [];
  const add = (k: ProjectKind) => !kinds.includes(k) && kinds.push(k);
  const ports: { port: number; source: string }[] = [];
  const compat: CompatibilityNote[] = [];
  const warnings: string[] = [];

  // ----------------------------------------------------------- project kind
  const rootIndex = src.text('index.html');
  const indexNeedsBuild = rootIndex !== undefined && /<script[^>]+type=["']module["'][^>]+src=["']\/?src\/[^"']+\.(?:ts|tsx|jsx|vue|svelte|js)["']/i.test(rootIndex);
  if (node) {
    if (hasNode('vite') || hasNode('@sveltejs/kit')) add('vite');
    if (hasNode('next')) add('nextjs');
    if (hasNode('react-scripts')) add('create-react-app');
    if (['vue', 'svelte', '@angular/core', 'astro', 'nuxt', 'gatsby', 'react', 'preact', 'solid-js'].some(hasNode) && !kinds.length) add('frontend-other');
    const start = node.scripts.get('start') ?? '';
    if (['express', 'fastify', 'koa', '@nestjs/core', '@hapi/hapi', 'hono', 'socket.io'].some(hasNode) || /^\s*(node|nodemon|ts-node|tsx|bun)\s+\S+\.(m?[jt]s|cjs)\b/.test(start)) add('node-server');
    if (!kinds.length) add('node-library');
  }
  if (rootIndex !== undefined && !indexNeedsBuild && !kinds.some((k) => ['vite', 'nextjs', 'create-react-app', 'frontend-other'].includes(k))) add('static-site');
  if (!node && rootIndex === undefined && ['docs/index.html', 'public/index.html', 'site/index.html'].some((p) => src.has(p))) add('static-site');
  const pyWeb = ['flask', 'django', 'fastapi', 'starlette', 'streamlit', 'gradio', 'dash', 'tornado', 'aiohttp', 'sanic', 'quart', 'pyramid'].find(hasPy) ?? (src.has('manage.py') ? 'django' : undefined);
  if (py || src.find(/^[^/]+\.py$/).length > 0) {
    if (pyWeb) add('python-web');
    else if (['main.py', 'app.py', 'run.py', '__main__.py'].some((f) => src.has(f)) || stack.scripts.some((s) => s.source.startsWith('pyproject'))) add('python-app');
    else if (py) add('python-library');
  }
  if (stack.goModule) add('go');
  if (stack.cargo) add('rust');
  if (infra.dockerfiles.some((d) => !d.path.includes('/'))) add('docker');
  if (infra.compose.some((c) => !c.path.includes('/'))) add('compose');
  if (!kinds.length) add('unknown');
  const priority: ProjectKind[] = ['nextjs', 'vite', 'create-react-app', 'frontend-other', 'node-server', 'python-web', 'static-site', 'go', 'rust', 'python-app', 'compose', 'docker', 'node-library', 'python-library', 'unknown'];
  const primary = priority.find((k) => kinds.includes(k)) ?? 'unknown';

  // ------------------------------------------------------------------ ports
  const scriptText = [...(node?.scripts.values() ?? [])].join('\n');
  for (const m of scriptText.matchAll(/(?:--port[ =]|-p\s+|PORT=)(\d{2,5})\b/g)) addPort(ports, Number(m[1]), 'package.json script');
  const viteCfg = ['vite.config.ts', 'vite.config.js', 'vite.config.mjs'].map((p) => src.text(p)).find((t) => t !== undefined);
  const viteCfgPort = viteCfg ? /port\s*:\s*(\d{2,5})/.exec(viteCfg)?.[1] : undefined;
  if (viteCfgPort) addPort(ports, Number(viteCfgPort), 'vite.config server.port');
  if (kinds.includes('vite')) addPort(ports, 5173, 'Vite dev server default');
  if (kinds.includes('nextjs') || kinds.includes('create-react-app')) addPort(ports, 3000, `${kinds.includes('nextjs') ? 'Next.js' : 'Create React App'} default`);
  if (hasNode('@angular/core')) addPort(ports, 4200, 'Angular CLI default');
  if (hasNode('astro')) addPort(ports, 4321, 'Astro default');
  for (const p of src.textPaths()) {
    if (isVendored(p) || p.split('/').length > 3) continue;
    const t = src.text(p);
    if (!t || t.length > 500_000) continue;
    if (/\.(m?[jt]s|cjs)$/.test(p)) {
      const m = /\.listen\(\s*(\d{2,5})\b|PORT\s*(?:\|\||\?\?)\s*['"]?(\d{2,5})/.exec(t);
      if (m) addPort(ports, Number(m[1] ?? m[2]), `${p}`);
    } else if (p.endsWith('.py')) {
      const m = /\.run\([^)]*port\s*=\s*(\d{2,5})|--port[ =](\d{2,5})|getenv\(\s*["']PORT["']\s*,\s*["']?(\d{2,5})|environ\.get\(\s*["']PORT["']\s*,\s*["']?(\d{2,5})/.exec(t);
      if (m) addPort(ports, Number(m[1] ?? m[2] ?? m[3] ?? m[4]), p);
    } else if (p.endsWith('.go')) {
      const m = /ListenAndServe(?:TLS)?\(\s*"[^":]*:(\d{2,5})"|\.Run\(\s*":(\d{2,5})"|Listen\(\s*":(\d{2,5})"/.exec(t);
      if (m) addPort(ports, Number(m[1] ?? m[2] ?? m[3]), p);
    } else if (p.endsWith('.rs')) {
      const m = /bind\(\s*(?:\(\s*\[[^\]]*\]\s*,\s*(\d{2,5})|"[^":]*:(\d{2,5})")/.exec(t);
      if (m) addPort(ports, Number(m[1] ?? m[2]), p);
    }
  }
  const pyDefaults: Record<string, number> = { flask: 5000, django: 8000, fastapi: 8000, starlette: 8000, streamlit: 8501, gradio: 7860, dash: 8050 };
  if (pyWeb && pyDefaults[pyWeb]) addPort(ports, pyDefaults[pyWeb] as number, `${pyWeb} default`);
  for (const d of infra.dockerfiles) for (const e of d.exposes) addPort(ports, e, `${d.path} EXPOSE`);
  for (const c of infra.compose) for (const s of c.services) for (const p of s.ports) {
    const host = Number.parseInt(p.split(':').length >= 2 ? (p.split(':').at(-2) as string) : p, 10);
    if (Number.isInteger(host)) addPort(ports, host, `${c.path} service ${s.name}`);
  }

  // --------------------------------------------------------------- services
  const services: { name: string; source: string }[] = [];
  const addService = (name: string, source: string) => !services.some((s) => s.name === name) && services.length < 10 && services.push({ name, source });
  for (const c of infra.compose) for (const s of c.services) {
    const hit = DB_IMAGES.find(([re]) => re.test(s.image ?? ''));
    if (hit) addService(hit[1], `${c.path} service "${s.name}"`);
  }
  for (const v of env.vars) {
    const hit = DB_ENV.find(([re]) => re.test(v.name));
    if (hit) addService(hit[1], `environment variable ${v.name}`);
  }
  for (const s of stack.stack) if (s.kind === 'database') addService(s.name.replace(/ client$/, ''), s.evidence);
  // A specific database makes the generic "A SQL database" redundant.
  if (services.some((s) => /PostgreSQL|MySQL|SQLite/.test(s.name))) {
    const i = services.findIndex((s) => s.name === 'A SQL database');
    if (i !== -1) services.splice(i, 1);
  }

  // ---------------------------------------------------------------- env
  const envFile = env.exampleFiles.find((p) => !p.includes('/')) ?? env.exampleFiles[0];
  // "Required" = documented in an example env file / Compose, or read by application code
  // (not only by tests, CI, build or helper scripts).
  const toolingPath = /^(\.github|\.gitlab|\.circleci|scripts?|tools?|ci|bin|tests?|__tests__|spec|e2e|benchmarks?|examples?|docs?)\/|(^|\/)(test_[^/]*|[^/]*[._](test|spec)\.[a-z]+|conftest\.py|[^/]*\.config\.[cm]?[jt]s)(:|$)/;
  const requiredEnv = env.vars
    .filter((v) => v.name !== 'PORT' && v.name !== 'HOST' && (v.documented || v.sources.some((s) => !/(^|\/)\.env/.test(s) && !toolingPath.test(s))))
    .map((v) => v.name)
    .slice(0, 40);

  // ------------------------------------------------------------------ steps
  const steps: LaunchStep[] = [];
  const dir = input.repo.name;
  steps.push({
    title: 'Get the exact commit that was analysed',
    commands: [`git clone ${input.repo.htmlUrl}.git`, `cd ${shq(dir)}`, `git checkout ${input.commitSha}`],
    ...(src.has('.gitmodules') ? { note: 'This repository uses Git submodules: run "git submodule update --init --recursive" after checkout.' } : {}),
  });
  if (envFile) {
    steps.push({
      title: 'Create your local environment file',
      commands: [`cp ${shq(envFile)} .env`],
      note: `Fill in real values for: ${requiredEnv.slice(0, 12).join(', ') || 'the variables listed in the file'}. Never commit .env.`,
    });
  } else if (requiredEnv.length) {
    steps.push({ title: 'Set required environment variables', commands: [], note: `The code reads: ${requiredEnv.slice(0, 12).join(', ')}. No example env file was found, so check the code for defaults.` });
  }
  const composeRoot = infra.compose.find((c) => !c.path.includes('/'));
  const dbServices = composeRoot?.services.filter((s) => DB_IMAGES.some(([re]) => re.test(s.image ?? ''))) ?? [];
  if (dbServices.length && primary !== 'compose') {
    steps.push({ title: 'Start the backing services', commands: [`docker compose${composeRoot && composeRoot.path !== 'docker-compose.yml' && composeRoot.path !== 'compose.yaml' ? ` -f ${shq(composeRoot.path)}` : ''} up -d ${dbServices.map((s) => shq(s.name)).join(' ')}`], note: 'Uses the Compose file in the repository; review it first.' });
  } else if (services.length && primary !== 'compose') {
    steps.push({ title: 'Provide the external services', commands: [], note: `The project appears to need: ${services.map((s) => s.name).join(', ')}.` });
  }

  const pmName = stack.packageManagers.find((p) => p.ecosystem === 'npm')?.name;
  const run = (script: string) => (pmName === 'Yarn' ? `yarn ${script}` : pmName === 'pnpm' ? `pnpm ${script}` : pmName === 'Bun' ? `bun run ${script}` : script === 'test' || script === 'start' ? `npm ${script}` : `npm run ${script}`);
  const nodeInstall = (): LaunchStep => {
    const lifecycle = stack.scripts.filter((s) => s.source === 'package.json' && s.kind === 'lifecycle').map((s) => s.name);
    const cmds: string[] = [];
    if (pmName === 'Yarn') cmds.push('corepack enable', src.has('.yarnrc.yml') ? 'yarn install --immutable --mode=skip-build' : 'yarn install --frozen-lockfile --ignore-scripts');
    else if (pmName === 'pnpm') cmds.push('corepack enable', 'pnpm install --frozen-lockfile --ignore-scripts');
    else if (pmName === 'Bun') cmds.push('bun install --frozen-lockfile --ignore-scripts');
    else cmds.push(src.has('package-lock.json') || src.has('npm-shrinkwrap.json') ? 'npm ci --ignore-scripts' : 'npm install --ignore-scripts');
    return {
      title: 'Install dependencies with install scripts disabled',
      commands: cmds,
      note: `Install scripts are skipped so nothing runs during installation.${lifecycle.length ? ` This project defines ${lifecycle.join(', ')}; read them, and if they are needed run them explicitly afterwards.` : ''}${NATIVE_NODE.some(hasNode) ? ' Native modules (for example ' + NATIVE_NODE.filter(hasNode).slice(0, 3).join(', ') + ') may need "npm rebuild" after you review them.' : ''}`,
    };
  };
  const portText = (fallback?: number) => {
    const p = ports[0]?.port ?? fallback;
    return p ? `Then open http://localhost:${p}` : undefined;
  };

  if (['vite', 'nextjs', 'create-react-app', 'frontend-other', 'node-server', 'node-library'].includes(primary) && node) {
    if (allNode.size > 0 || stack.scripts.some((s) => s.source === 'package.json' && s.kind === 'lifecycle')) steps.push(nodeInstall());
    const dev = node.scripts.has('dev') ? 'dev' : node.scripts.has('start') ? 'start' : node.scripts.has('serve') ? 'serve' : undefined;
    if (primary === 'node-library') {
      if (node.scripts.has('build')) steps.push({ title: 'Build', commands: [run('build')] });
    } else if (dev) {
      steps.push({ title: 'Start the development server', commands: [run(dev)], ...(portText() ? { note: portText() } : {}) });
    } else {
      steps.push({ title: 'Start the application', commands: [], note: 'No dev/start script is defined; check the entry points listed in the overview.' });
    }
    if (node.scripts.has('build') && primary !== 'node-library') {
      steps.push({ title: 'Production build', commands: [run('build'), ...(node.scripts.has('preview') ? [run('preview')] : node.scripts.has('start') && primary !== 'node-server' ? [run('start')] : [])] });
    }
  } else if (primary === 'static-site') {
    const root = rootIndex !== undefined ? '.' : (['docs', 'public', 'site'].find((d) => src.has(`${d}/index.html`)) ?? '.');
    steps.push({ title: 'Serve the static files', commands: [`python3 -m http.server 8000 --bind 127.0.0.1${root !== '.' ? ` --directory ${root}` : ''}`], note: 'Then open http://localhost:8000. Any static file server works; nothing is installed.' });
  } else if (primary === 'python-web' || primary === 'python-app' || primary === 'python-library') {
    const cmds = ['python3 -m venv .venv', 'source .venv/bin/activate'];
    const pyPm = stack.packageManagers.find((p) => p.ecosystem === 'PyPI')?.name;
    if (pyPm === 'Poetry') cmds.splice(0, 2, 'poetry install');
    else if (pyPm === 'uv') cmds.splice(0, 2, 'uv sync');
    else if (pyPm === 'Pipenv') cmds.splice(0, 2, 'pipenv install --dev');
    else {
      const req = stack.python?.sources.find((s) => /^requirements\.txt$/.test(s)) ?? stack.python?.sources.find((s) => s.includes('requirements'));
      if (req) cmds.push(`pip install -r ${shq(req)}`);
      else if (src.has('pyproject.toml')) cmds.push('pip install -e .');
    }
    steps.push({ title: 'Create a virtual environment and install dependencies', commands: cmds, note: 'Installing Python packages can run their build scripts. Prefer wheels: add --only-binary=:all: to pip if your platform has wheels for every package.' });
    const prefix = pyPm === 'Poetry' ? 'poetry run ' : pyPm === 'uv' ? 'uv run ' : pyPm === 'Pipenv' ? 'pipenv run ' : '';
    if (pyWeb === 'django' || src.has('manage.py')) steps.push({ title: 'Prepare the database and start Django', commands: [`${prefix}python manage.py migrate`, `${prefix}python manage.py runserver`], note: 'Then open http://localhost:8000' });
    else if (pyWeb === 'flask') {
      const appFile = ['app.py', 'wsgi.py', 'main.py', 'run.py'].find((f) => src.has(f));
      steps.push({ title: 'Start Flask', commands: [appFile && appFile !== 'app.py' && appFile !== 'wsgi.py' ? `${prefix}python ${appFile}` : `${prefix}flask --app ${appFile?.replace(/\.py$/, '') ?? 'app'} run`], note: portText(5000) ?? 'Then open http://localhost:5000' });
    } else if (pyWeb === 'fastapi' || pyWeb === 'starlette') {
      const target = src.textPaths().filter((p) => p.endsWith('.py') && !isVendored(p) && p.split('/').length <= 3).map((p) => ({ p, m: /^(\w+)\s*=\s*(?:FastAPI|Starlette)\(/m.exec(src.text(p) ?? '') })).find((x) => x.m);
      const mod = target ? `${target.p.replace(/\.py$/, '').replace(/\//g, '.')}:${target.m?.[1]}` : 'main:app';
      steps.push({ title: 'Start the ASGI server', commands: [`${prefix}uvicorn ${mod} --reload`], note: 'Then open http://localhost:8000/docs' });
    } else if (pyWeb === 'streamlit') {
      const app = ['streamlit_app.py', 'app.py', 'main.py'].find((f) => src.has(f)) ?? 'app.py';
      steps.push({ title: 'Start Streamlit', commands: [`${prefix}streamlit run ${app}`], note: 'Then open http://localhost:8501' });
    } else if (pyWeb === 'gradio') {
      const app = ['app.py', 'main.py'].find((f) => src.has(f)) ?? 'app.py';
      steps.push({ title: 'Start the Gradio app', commands: [`${prefix}python ${app}`], note: 'Then open http://localhost:7860' });
    } else if (primary === 'python-app') {
      const app = ['main.py', 'app.py', 'run.py'].find((f) => src.has(f));
      if (app) steps.push({ title: 'Run the application', commands: [`${prefix}python ${app}`] });
    }
  } else if (primary === 'go') {
    const cmds = src.find(/^cmd\/[^/]+\/main\.go$/).slice(0, 3).map((p) => `go run ./${p.replace(/\/main\.go$/, '')}`);
    steps.push({ title: 'Download modules and run', commands: ['go mod download', ...(src.has('main.go') ? ['go run .'] : cmds.length ? cmds : ['go build ./...'])], ...(portText() ? { note: portText() } : {}) });
  } else if (primary === 'rust') {
    steps.push({ title: 'Build and run', commands: [src.has('src/main.rs') || src.find(/^src\/bin\//).length ? 'cargo run' : 'cargo build'], note: 'Cargo build scripts (build.rs) and procedural macros run on your machine during the build.' });
  } else if (primary === 'compose' && composeRoot) {
    steps.push({ title: 'Start all services', commands: [`docker compose${composeRoot.path === 'docker-compose.yml' || composeRoot.path === 'compose.yaml' ? '' : ` -f ${shq(composeRoot.path)}`} up --build`], note: portText() ?? 'Check the published ports in the Compose file.' });
  } else if (primary === 'docker') {
    const tag = input.repo.name.toLowerCase().replace(/[^a-z0-9_.-]/g, '-').slice(0, 60) || 'app';
    const p = infra.dockerfiles[0]?.exposes[0];
    steps.push({ title: 'Build and run the container', commands: [`docker build -t ${tag} .`, `docker run --rm ${p ? `-p 127.0.0.1:${p}:${p} ` : ''}${tag}`], ...(p ? { note: `Then open http://localhost:${p}` } : {}) });
  }
  if (stack.tests.commands.length) {
    steps.push({ title: 'Run the tests', commands: stack.tests.commands.map((c) => (c.command === 'npm test' ? run('test') : c.command)).slice(0, 3) });
  }

  // ------------------------------------------------- compatibility & warnings
  const engines = stack.stack.find((s) => s.kind === 'runtime' && s.name === 'Node.js');
  if (engines?.version) {
    const major = majorOf(engines.version);
    if (major !== undefined && major < 18) compat.push({ level: 'warning', message: `Requires Node.js ${engines.version}, which is end-of-life. Current Node.js releases may not run it, and old versions no longer get security fixes.`, evidence: engines.evidence });
    else compat.push({ level: 'info', message: `Declares Node.js ${engines.version}.`, evidence: engines.evidence });
  }
  if (py?.requiresPython) {
    const m = /3\.(\d+)/.exec(py.requiresPython);
    if (m && Number(m[1]) < 9 && !/>=?\s*3\.\d/.test(py.requiresPython)) compat.push({ level: 'warning', message: `Targets Python ${py.requiresPython}; Python 3.8 and older are end-of-life.`, evidence: 'requires-python' });
    else compat.push({ level: 'info', message: `Declares Python ${py.requiresPython}.` });
  }
  if (stack.goModule?.goVersion) compat.push({ level: 'info', message: `Needs Go ${stack.goModule.goVersion} or newer (go.mod).` });
  const npmLocks = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock'].filter((l) => src.has(l));
  if (npmLocks.length > 1) compat.push({ level: 'warning', message: `Several JavaScript lockfiles are committed (${npmLocks.join(', ')}). Different package managers will install different versions.` });
  if (node && npmLocks.length === 0 && allNode.size > 0) compat.push({ level: 'warning', message: 'No JavaScript lockfile: installs are not reproducible and versions can change between machines.' });
  const nativeNode = NATIVE_NODE.filter(hasNode);
  if (nativeNode.length) compat.push({ level: 'warning', message: `Native Node.js modules (${nativeNode.join(', ')}) may need a C/C++ toolchain and Python to install.` });
  const nativePy = NATIVE_PY.filter(hasPy);
  if (nativePy.length) compat.push({ level: 'warning', message: `Python packages with native parts (${nativePy.join(', ')}) may need system libraries or compilers.` });
  if (['torch', 'tensorflow', 'jax', 'jaxlib'].some(hasPy)) compat.push({ level: 'info', message: 'Uses a large machine-learning framework: expect multi-gigabyte downloads; GPU acceleration needs matching drivers.' });
  if (src.has('.gitmodules')) compat.push({ level: 'blocker', message: 'Uses Git submodules (listed under Configuration). Their contents are not part of GitHub source archives, so this analysis and any download from GitHub miss them. Clone with --recurse-submodules.', evidence: '.gitmodules' });
  const attrs = src.text('.gitattributes');
  const lfs = input.lfs;
  if (lfs && lfs.pointerCount > 0) {
    compat.push({
      level: 'warning',
      message: `${lfs.pointerCount} file${lfs.pointerCount === 1 ? ' is a Git LFS pointer' : 's are Git LFS pointers'} (${(lfs.pointerBytes / 1048576).toFixed(1)} MB of real content not in the archive or this analysis). Install git-lfs and run "git lfs pull" after cloning.`,
      evidence: '.gitattributes',
    });
  } else if (attrs && /filter=lfs/.test(attrs)) {
    compat.push({ level: 'warning', message: 'Uses Git LFS: large files appear as small pointer files in archives. Install git-lfs and run "git lfs pull" after cloning.', evidence: '.gitattributes' });
  }
  if (input.skippedSymlinks > 0) compat.push({ level: 'info', message: `${input.skippedSymlinks} symbolic link${input.skippedSymlinks === 1 ? ' was' : 's were'} not analysed; they exist in a real clone.` });
  if (src.files.some((f) => f.path.startsWith('node_modules/'))) compat.push({ level: 'warning', message: 'node_modules is committed. It may be stale or platform-specific; reinstall instead of using it.' });
  if (node && (Object.hasOwn(node.pkg, 'workspaces') || src.has('pnpm-workspace.yaml') || src.has('lerna.json') || src.has('turbo.json') || src.has('nx.json'))) compat.push({ level: 'info', message: 'This is a monorepo. The steps cover the root; individual packages may have their own scripts.' });
  if (/\bset [A-Z_]+=|\bcmd \/c\b/.test(scriptText)) compat.push({ level: 'warning', message: 'npm scripts use Windows-only syntax ("set VAR=" or "cmd /c"); they may fail on macOS and Linux.' });
  else if (/(^|&&|;)\s*[A-Z_]+=\S+\s+\S/m.test(scriptText) && !hasNode('cross-env')) compat.push({ level: 'info', message: 'npm scripts set variables with Unix syntax (VAR=value cmd); on Windows use WSL or cross-env.' });
  const onlyWin = src.files.some((f) => /\.(bat|cmd|ps1)$/.test(f.path)) && !src.files.some((f) => /\.sh$/.test(f.path));
  if (onlyWin) compat.push({ level: 'info', message: 'Helper scripts are Windows-only (.bat/.cmd/.ps1).' });
  if (services.length) compat.push({ level: 'info', message: `Needs external services: ${services.map((s) => s.name).join(', ')}.` });
  for (const e of infra.parseErrors.slice(0, 5)) compat.push({ level: 'warning', message: `Could not parse ${e}` });
  if (kinds.includes('nextjs')) compat.push({ level: 'info', message: 'Next.js apps that use server features need a Node.js server; only apps configured with output: "export" produce static files.' });

  warnings.push('These commands run code from this repository and its dependencies on your computer. Review the scripts first; for code you do not trust, use a disposable VM or container.');
  if (stack.scripts.some((s) => s.source === 'package.json' && s.kind === 'lifecycle')) warnings.push('package.json defines install lifecycle scripts; the install step below skips them.');
  if (env.committedEnvFiles.length) warnings.push(`A real environment file is committed (${env.committedEnvFiles.join(', ')}). Do not reuse its values.`);

  // ------------------------------------------------------------------ preview
  const preview = planPreview(src, kinds, node, viteCfg, indexNeedsBuild);

  const summaryParts: Record<ProjectKind, string> = {
    'static-site': 'Static website (HTML/CSS/JavaScript, no build step)',
    vite: 'Vite front-end application',
    nextjs: 'Next.js application',
    'create-react-app': 'Create React App front-end',
    'frontend-other': 'JavaScript front-end application',
    'node-server': 'Node.js server application',
    'node-library': 'Node.js package or tool',
    'python-web': `Python web application${pyWeb ? ` (${pyWeb})` : ''}`,
    'python-app': 'Python application',
    'python-library': 'Python package',
    docker: 'Containerised application (Dockerfile)',
    compose: 'Multi-service application (Docker Compose)',
    go: 'Go module',
    rust: 'Rust crate',
    unknown: 'Project type not recognised',
  };

  return {
    plan: {
      kinds,
      primary,
      summary: summaryParts[primary],
      ...(stack.packageManagers[0] ? { packageManager: stack.packageManagers[0].name } : {}),
      ports,
      services,
      ...(envFile ? { envFile } : {}),
      requiredEnv,
      steps,
      warnings,
      preview,
    },
    compatibility: compat,
  };
}

function planPreview(src: SourceView, kinds: ProjectKind[], node: StackAnalysis['node'], viteCfg: string | undefined, indexNeedsBuild: boolean): PreviewPlan {
  if (kinds.includes('static-site')) {
    const root = src.has('index.html') && !indexNeedsBuild ? '' : (['docs', 'public', 'site'].find((d) => src.has(`${d}/index.html`)) ?? '');
    return { kind: 'static', root, reason: `Static files served directly from the repository${root ? ` (${root}/)` : ''}. No code runs on the server; the page's own scripts run in your browser, isolated from this site.` };
  }
  const builtDir = ['dist', 'build', 'out'].find((d) => src.has(`${d}/index.html`));
  if (builtDir && !src.find(new RegExp(`^${builtDir}/`)).some((p) => p.endsWith('.ts'))) {
    return { kind: 'static', root: builtDir, reason: `The repository includes built output in ${builtDir}/. It is served as committed, which may be older than the source.` };
  }
  const buildScript = node?.scripts.get('build');
  if (buildScript && (kinds.includes('vite') || kinds.includes('create-react-app') || kinds.includes('frontend-other') || kinds.includes('nextjs'))) {
    if (kinds.includes('nextjs')) {
      const nextCfg = ['next.config.js', 'next.config.mjs', 'next.config.ts'].map((p) => src.text(p)).find((t) => t !== undefined) ?? '';
      if (!/output\s*:\s*["']export["']/.test(nextCfg)) return { kind: 'none', reason: 'This Next.js app needs a running Node.js server (it is not configured for static export). Live server previews are not supported; use the setup steps to run it locally.' };
      return { kind: 'build', root: 'out', buildCheckId: 'node.npm-build', reason: 'Static export: needs "npm run build" in the sandbox before it can be previewed.' };
    }
    const outDir = viteCfg ? /outDir\s*:\s*["']([A-Za-z0-9._/-]{1,60})["']/.exec(viteCfg)?.[1] : undefined;
    const root = (outDir ?? (kinds.includes('create-react-app') ? 'build' : 'dist')).replace(/^\.\//, '').replace(/\/$/, '');
    return { kind: 'build', root, buildCheckId: 'node.npm-build', reason: `Needs "npm run build" before it can be previewed. The build runs only in a verified sandbox; the output in ${root}/ is then served as static files.` };
  }
  if (kinds.some((k) => ['node-server', 'python-web', 'go', 'rust', 'docker', 'compose', 'python-app'].includes(k))) {
    return { kind: 'none', reason: 'This project runs as a server or program. Live previews of running servers are not supported in this version, because they need a long-running process with network access in a verified sandbox. Use the setup steps to run it locally.' };
  }
  return { kind: 'none', reason: 'No previewable web front-end was found.' };
}

