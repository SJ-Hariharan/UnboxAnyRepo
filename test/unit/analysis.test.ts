import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeArchive } from '../../src/source/archive.ts';
import { textSkipReason, looksBinary, isSecondaryText } from '../../src/analysis/paths.ts';
import { repoArchive } from '../helpers/tarbuilder.ts';
import { analyseOffline } from '../helpers/analysis.ts';
import { groupRepeats, dedupe } from '../../src/analysis/index.ts';
import { parseDockerfile, parseYamlDoc } from '../../src/analysis/infra.ts';
import type { Finding } from '../../src/analysis/types.ts';

const LIM = { maxCompressedBytes: 2e7, maxUncompressedBytes: 2e7, maxFiles: 5000, maxFileBytes: 4e6 };

async function analyse(files: Record<string, string>, budget = 8 * 1024 * 1024) {
  const snap = await sanitizeArchive(repoArchive(files), LIM, {
    collectText: { maxTotalBytes: budget, maxSecondaryBytes: Math.floor(budget / 4), isSecondary: isSecondaryText, skipReason: (p, s) => textSkipReason(p, s, 512 * 1024), isBinary: looksBinary },
  });
  return analyseOffline(snap);
}

const rules = (fs: Finding[]) => fs.map((f) => f.ruleId);

test('stack, package manager, scripts and tests are read from manifests', async () => {
  const a = await analyse({
    'package.json': JSON.stringify({ scripts: { dev: 'vite --port 5174', build: 'vite build', test: 'vitest run', postinstall: 'node setup.js' }, dependencies: { react: '^18.3.0' }, devDependencies: { vite: '^5.4.0', vitest: '^2.0.0' }, engines: { node: '>=20' } }),
    'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/react': { version: '18.3.1' }, 'node_modules/@scope/pkg': { version: '1.0.0' } } }),
    'index.html': '<!doctype html><script type="module" src="/src/main.jsx"></script>',
    'src/main.jsx': 'console.log(1)',
  });
  const names = a.stack.map((s) => s.name);
  for (const n of ['React', 'Vite', 'Vitest', 'Node.js']) assert.ok(names.includes(n), n);
  assert.equal(a.packageManagers[0]?.name, 'npm');
  assert.equal(a.packageManagers[0]?.lockfile, 'package-lock.json');
  assert.deepEqual(a.scripts.find((s) => s.name === 'postinstall')?.kind, 'lifecycle');
  assert.equal(a.launch.primary, 'vite');
  assert.equal(a.launch.preview.kind, 'build');
  assert.equal(a.launch.preview.root, 'dist');
  assert.ok(a.launch.ports.some((p) => p.port === 5174), 'port from the dev script');
  assert.ok(a.launch.steps.some((s) => s.commands.includes('npm ci --ignore-scripts')), 'install skips lifecycle scripts');
  assert.deepEqual(a.dependencies.packages.map((p) => `${p.name}@${p.version}`).sort(), ['@scope/pkg@1.0.0', 'react@18.3.1']);
  assert.ok(rules(a.findings).includes('install.lifecycle-script'));
});

test('static sites get a static preview; committed build output is preferred over nothing', async () => {
  const a = await analyse({ 'index.html': '<!doctype html><link rel="stylesheet" href="s.css">', 's.css': 'body{}' });
  assert.equal(a.launch.primary, 'static-site');
  assert.equal(a.launch.preview.kind, 'static');
  assert.equal(a.launch.preview.root, '');
  const b = await analyse({ 'package.json': JSON.stringify({ dependencies: { express: '4.0.0' }, scripts: { start: 'node server.js' } }), 'server.js': 'app.listen(3000)' });
  assert.equal(b.launch.primary, 'node-server');
  assert.equal(b.launch.preview.kind, 'none');
  assert.match(b.launch.preview.reason, /not supported/);
  assert.ok(b.launch.ports.some((p) => p.port === 3000));
});

test('Python web apps: framework, env names, services and run commands', async () => {
  const a = await analyse({
    'requirements.txt': 'fastapi==0.110.0\nuvicorn[standard]>=0.29\npsycopg2==2.9.9\n',
    'api/main.py': 'import os\nfrom fastapi import FastAPI\nserver = FastAPI()\nDB = os.environ["DATABASE_URL"]\nKEY = os.getenv("API_TOKEN")\n',
    '.env.example': 'DATABASE_URL=postgresql://user:password@localhost/db\nAPI_TOKEN=\n',
  });
  assert.equal(a.launch.primary, 'python-web');
  assert.ok(a.stack.some((s) => s.name === 'FastAPI'));
  assert.deepEqual(a.env.map((e) => e.name).sort(), ['API_TOKEN', 'DATABASE_URL']);
  assert.ok(a.launch.steps.some((s) => s.commands.some((c) => c === 'uvicorn api.main:server --reload')), JSON.stringify(a.launch.steps));
  assert.ok(a.launch.services.some((s) => /SQL/.test(s.name)));
  assert.ok(a.compatibility.some((c) => /native parts/.test(c.message)), 'psycopg2 needs build tools');
  // Exact pins are inventoried; ranges are not guessed.
  assert.deepEqual(a.dependencies.packages.map((p) => p.name).sort(), ['fastapi', 'psycopg2']);
  // Placeholder credentials in .env.example are not reported as leaks.
  assert.ok(!rules(a.findings).includes('secret.url-credentials'));
});

test('environment values are never copied into the result', async () => {
  const a = await analyse({ '.env': 'SECRET_TOKEN=zq8V3mLx92Kd0PqT\n', 'app.js': 'process.env.SECRET_TOKEN' });
  const json = JSON.stringify(a);
  assert.ok(!json.includes('zq8V3mLx92Kd0PqT'));
  assert.ok(a.env.some((e) => e.name === 'SECRET_TOKEN'));
  assert.ok(rules(a.findings).includes('secret.committed-env-file'));
});

test('secrets: known formats found and redacted; placeholders and documented examples ignored', async () => {
  const gh = `ghp_${'A1b2C3d4E5'.repeat(4).slice(0, 36)}`;
  const a = await analyse({
    'config.js': `const token = "${gh}";\nconst aws = "AKIAIOSFODNN7EXAMPLE";\nconst password = "changeme";\nconst apiKey = "Qm9vYmFyQmF6UXV4MTIzNDU2";\n`,
    'deploy/key.pem': '-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\n',
    'tests/fixture.py': `TOKEN = "${gh}"\n`,
  });
  const json = JSON.stringify(a.findings);
  assert.ok(!json.includes(gh), 'secret value is redacted');
  assert.ok(!json.includes('MIIEow'));
  const ghFindings = a.findings.filter((f) => f.ruleId === 'secret.github-token');
  assert.equal(ghFindings.length, 2);
  assert.equal(ghFindings.find((f) => f.file === 'config.js')?.severity, 'critical');
  assert.equal(ghFindings.find((f) => f.file === 'tests/fixture.py')?.severity, 'high', 'downgraded in test code');
  assert.ok(ghFindings.every((f) => f.status === 'unverified'));
  assert.ok(rules(a.findings).includes('secret.private-key'));
  assert.ok(!rules(a.findings).includes('secret.aws-access-key'), 'AWS documentation example key ignored');
  const generic = a.findings.filter((f) => f.ruleId === 'secret.hardcoded-credential');
  assert.equal(generic.length, 1, 'placeholder "changeme" ignored, random-looking apiKey reported');
  assert.equal(generic[0]?.status, 'heuristic');
});

test('code rules: injection, deserialization and TLS patterns are flagged as heuristics', async () => {
  const a = await analyse({
    'server.js': [
      "const { exec } = require('child_process');",
      'exec(`ls ${req.query.dir}`);',
      'db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);',
      "https.request({ rejectUnauthorized: false });",
      '// exec(`commented ${out}`)',
    ].join('\n'),
    'worker.py': 'import pickle, yaml, subprocess, os\npickle.loads(blob)\nyaml.load(text)\nyaml.load(text, Loader=yaml.SafeLoader)\nsubprocess.run(cmd, shell=True)\ncur.execute(f"SELECT * FROM t WHERE x = {x}")\nos.system("echo " + name)\n',
    'cli.py': 'import sys\nopen(sys.argv[1]).read()\n',
  });
  const r = rules(a.findings);
  for (const id of ['cmd.js-exec-interpolated', 'sql.js-concat', 'net.tls-verify-disabled', 'deser.py-pickle', 'deser.py-yaml-load', 'cmd.py-shell-true', 'sql.py-format', 'cmd.py-os-system']) assert.ok(r.includes(id), id);
  assert.equal(a.findings.filter((f) => f.ruleId === 'deser.py-yaml-load').length, 1, 'safe loader not flagged');
  assert.equal(a.findings.filter((f) => f.ruleId === 'cmd.js-exec-interpolated').length, 1, 'comments ignored');
  assert.ok(!r.includes('path.request-to-fs'), 'command-line arguments are not treated as attacker input');
  assert.ok(a.findings.filter((f) => f.method === 'builtin-rule' && f.category !== 'install-script').every((f) => f.status === 'heuristic' || f.category === 'secret'));
  for (const f of a.findings) {
    assert.match(f.id, /^UAR-[A-Z]+-[a-f0-9]{12}$/);
    assert.ok(f.risk.length > 10 && f.remediation.length > 10, f.ruleId);
  }
});

test('Dockerfile, Compose and GitHub Actions rules', async () => {
  const a = await analyse({
    Dockerfile: 'FROM node:latest AS build\nRUN curl -sL https://x.invalid/i.sh | bash\nFROM build\nENV API_TOKEN=abcd1234secret\nEXPOSE 8080\n',
    'docker-compose.yml': 'services:\n  app:\n    image: app\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n  db:\n    image: postgres:16\n    ports: ["5432:5432"]\n  cache:\n    image: redis\n    ports: ["127.0.0.1:6379:6379"]\n',
    '.github/workflows/ci.yml': 'on: pull_request_target\npermissions: write-all\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: third/party@v2\n      - uses: other/pinned@0123456789abcdef0123456789abcdef01234567\n      - run: echo "${{ github.event.issue.title }}"\n',
    '.github/workflows/ok.yml': 'on: push\npermissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n',
  });
  const r = rules(a.findings);
  for (const id of ['docker.runs-as-root', 'docker.unpinned-base-image', 'docker.curl-pipe-shell', 'docker.secret-in-env', 'compose.privileged', 'compose.docker-socket', 'compose.database-port-exposed', 'ci.write-all-permissions', 'ci.pr-target-checkout', 'ci.unpinned-third-party-action', 'ci.script-injection']) assert.ok(r.includes(id), id);
  assert.equal(a.findings.filter((f) => f.ruleId === 'compose.database-port-exposed').length, 1, 'localhost-bound redis is fine');
  assert.equal(a.findings.filter((f) => f.ruleId === 'ci.unpinned-third-party-action').length, 1, 'SHA-pinned action is fine');
  assert.ok(!a.findings.some((f) => f.file === '.github/workflows/ok.yml'), 'least-privilege workflow has no findings');
  assert.equal(a.findings.find((f) => f.ruleId === 'compose.docker-socket')?.severity, 'critical');
  assert.ok(!JSON.stringify(a.findings).includes('abcd1234secret'));
  assert.deepEqual(a.dockerfiles[0]?.exposes, [8080]);
  assert.deepEqual(a.compose[0]?.services.map((s) => s.name), ['app', 'db', 'cache']);
});

test('hostile YAML: alias bombs and broken files are reported, not expanded', async () => {
  const bomb = 'a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\nservices: [*d,*d,*d,*d,*d,*d,*d,*d,*d]\n';
  const r = parseYamlDoc(bomb);
  assert.equal(r.doc, undefined);
  assert.ok(r.error);
  const a = await analyse({ 'compose.yaml': bomb, '.github/workflows/x.yml': 'on: [push\njobs: {' });
  assert.ok(a.compatibility.some((c) => /Could not parse/.test(c.message)));
});

test('Dockerfile parser joins continuation lines and keeps line numbers', () => {
  const ins = parseDockerfile('# c\nFROM alpine:3.20\nRUN apk add \\\n  curl \\\n  git\nUSER app\n');
  assert.deepEqual(ins.map((i) => [i.op, i.line]), [['FROM', 2], ['RUN', 3], ['USER', 6]]);
  assert.match(ins[1]?.args ?? '', /apk add\s+curl\s+git/);
});

test('lockfile parsers: yarn v1, yarn berry, pnpm, poetry, Cargo, Pipfile.lock', async () => {
  const yarnV1 = '# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.24.0"\n  resolved "x"\n\nlodash@^4.17.0:\n  version "4.17.20"\n';
  const a = await analyse({ 'package.json': '{"dependencies":{"lodash":"^4"}}', 'yarn.lock': yarnV1 });
  assert.deepEqual(a.dependencies.packages.map((p) => `${p.name}@${p.version}`).sort(), ['@babel/core@7.24.0', 'lodash@4.17.20']);
  const berry = '__metadata:\n  version: 8\n\n"lodash@npm:^4.17.0":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n';
  const b = await analyse({ 'package.json': '{}', 'yarn.lock': berry });
  assert.deepEqual(b.dependencies.packages.map((p) => `${p.name}@${p.version}`), ['lodash@4.17.21']);
  const pnpm = "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.21:\n    resolution: {integrity: x}\n  '@types/node@20.1.0':\n    resolution: {integrity: y}\n";
  const c = await analyse({ 'package.json': '{}', 'pnpm-lock.yaml': pnpm });
  assert.deepEqual(c.dependencies.packages.map((p) => `${p.name}@${p.version}`).sort(), ['@types/node@20.1.0', 'lodash@4.17.21']);
  const d = await analyse({
    'pyproject.toml': '[tool.poetry]\nname="x"\n[tool.poetry.dependencies]\npython="^3.11"\nrequests="^2"\n',
    'poetry.lock': '[[package]]\nname = "requests"\nversion = "2.31.0"\n',
    'Cargo.toml': '[package]\nname="c"\n[dependencies]\nserde="1"\n',
    'Cargo.lock': '[[package]]\nname = "c"\nversion = "0.1.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.200"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
    'Pipfile.lock': JSON.stringify({ default: { flask: { version: '==3.0.0' } }, develop: {} }),
  });
  assert.deepEqual(d.dependencies.packages.map((p) => `${p.ecosystem}:${p.name}@${p.version}`).sort(), ['PyPI:flask@3.0.0', 'PyPI:requests@2.31.0', 'crates.io:serde@1.0.200']);
});

test('compatibility notes: submodules, LFS, EOL runtimes, lockfile conflicts', async () => {
  const a = await analyse({
    '.gitmodules': '[submodule "x"]\n',
    '.gitattributes': '*.bin filter=lfs diff=lfs merge=lfs -text\n',
    'package.json': JSON.stringify({ engines: { node: '14.x' }, dependencies: { bcrypt: '5.0.0' } }),
    'package-lock.json': '{"packages":{}}',
    'yarn.lock': '',
  });
  const msgs = a.compatibility.map((c) => `${c.level}: ${c.message}`).join('\n');
  assert.match(msgs, /blocker: Uses Git submodules/);
  assert.match(msgs, /Git LFS/);
  assert.match(msgs, /end-of-life/);
  assert.match(msgs, /Several JavaScript lockfiles/);
  assert.match(msgs, /Native Node\.js modules \(bcrypt\)/);
});

test('finding ids are stable across runs and repeated matches are grouped', async () => {
  const files = { 'a.py': Array.from({ length: 6 }, (_, i) => `x${i} = pickle.loads(data${i})`).join('\n') };
  const one = await analyse(files);
  const two = await analyse(files);
  assert.deepEqual(one.findings.map((f) => f.id), two.findings.map((f) => f.id));
  const pickle = one.findings.filter((f) => f.ruleId === 'deser.py-pickle');
  assert.equal(pickle.length, 1);
  assert.match(pickle[0]?.title ?? '', /6 matches in this file/);
  assert.match(pickle[0]?.evidence ?? '', /also at lines 2, 3, 4, 5, 6/);
  // Same rule at the same place from a more precise tool wins.
  const base = { ruleId: 'r', title: 't', category: 'sql-injection' as const, severity: 'high' as const, confidence: 'medium' as const, status: 'heuristic' as const, file: 'x.py', startLine: 3, risk: 'r', remediation: 'r', references: [] };
  const merged = dedupe([{ ...base, id: 'UAR-CODE-1', method: 'builtin-rule' }, { ...base, id: 'UAR-SG-1', method: 'semgrep' }]);
  assert.deepEqual(merged.map((f) => f.method), ['semgrep']);
  assert.equal(groupRepeats([]).length, 0);
});

test('analysis budget: source code is kept before docs and data; coverage is reported', async () => {
  const files: Record<string, string> = {};
  for (let i = 0; i < 20; i++) files[`docs/page${i}.md`] = 'x'.repeat(10_000);
  files['zz/app.js'] = 'exec(`rm ${req.body.x}`)';
  const a = await analyse(files, 60_000);
  assert.ok(a.findings.some((f) => f.file === 'zz/app.js'), 'source analysed even though docs came first');
  assert.equal(a.coverage.complete, false);
  assert.ok((a.coverage.skipped.budget ?? 0) > 0);
});

test('binary and vendored files are skipped for analysis', () => {
  assert.equal(textSkipReason('node_modules/x/index.js', 10, 1000), 'vendored');
  assert.equal(textSkipReason('img/a.png', 10, 1000), 'binary');
  assert.equal(textSkipReason('dist/app.min.js', 10, 1000), 'generated');
  assert.equal(textSkipReason('big.js', 2000, 1000), 'too_large');
  assert.equal(textSkipReason('package-lock.json', 20_000, 1000), null, 'lockfiles get a larger allowance');
  assert.equal(looksBinary(Buffer.from([1, 2, 0, 3])), true);
});
