/**
 * Path classification for static analysis. Pure functions; no I/O.
 */

/** Directories whose contents are third-party or generated and are not analysed. */
const VENDORED_RE = /(^|\/)(node_modules|vendor|bower_components|\.venv|venv|env|site-packages|__pycache__|\.git|\.next|\.nuxt|\.svelte-kit|\.cache|coverage|target|\.gradle|Pods)(\/|$)/;
const GENERATED_RE = /(\.min\.(js|css)|\.map|\.bundle\.js|\.chunk\.js)$/i;

const BINARY_EXT = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'icns', 'bmp', 'tif', 'tiff', 'psd', 'avif', 'heic',
  'mp3', 'mp4', 'wav', 'ogg', 'webm', 'mov', 'avi', 'flac', 'm4a',
  'woff', 'woff2', 'ttf', 'otf', 'eot',
  'zip', 'gz', 'tgz', 'bz2', 'xz', '7z', 'rar', 'tar', 'jar', 'war', 'whl', 'egg', 'nupkg', 'crate',
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'key', 'numbers', 'pages',
  'exe', 'dll', 'so', 'dylib', 'a', 'o', 'obj', 'lib', 'bin', 'wasm', 'class', 'pyc', 'pyo', 'node',
  'sqlite', 'db', 'sqlite3', 'pack', 'idx', 'dat', 'pt', 'onnx', 'h5', 'pkl', 'npy', 'npz', 'parquet',
]);

/** Files that matter for dependency analysis even when large. */
const LOCKFILE_NAMES = new Set([
  'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock',
  'Pipfile.lock', 'poetry.lock', 'uv.lock', 'Cargo.lock', 'go.sum', 'Gemfile.lock', 'composer.lock',
  'packages.lock.json', 'pubspec.lock',
]);

export function baseName(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}

export function extension(p: string): string {
  const b = baseName(p);
  const i = b.lastIndexOf('.');
  return i <= 0 ? '' : b.slice(i + 1).toLowerCase();
}

export function isVendored(p: string): boolean {
  return VENDORED_RE.test(p);
}

export function isLockfile(p: string): boolean {
  return LOCKFILE_NAMES.has(baseName(p));
}

export function isBinaryByName(p: string): boolean {
  return BINARY_EXT.has(extension(p));
}

export type SkipReason = 'vendored' | 'binary' | 'generated' | 'too_large';

/** Decide whether a file's text should be kept for analysis, before reading the budget. */
export function textSkipReason(p: string, size: number, maxFileBytes: number): SkipReason | null {
  if (isVendored(p)) return 'vendored';
  // Tiny files are read even with a binary extension: Git LFS pointers look like that.
  // Real binaries are still dropped by looksBinary (NUL bytes).
  if (isBinaryByName(p)) return size <= 200 ? null : 'binary';
  if (isLockfile(p)) return size > maxFileBytes * 32 ? 'too_large' : null;
  if (GENERATED_RE.test(p)) return 'generated';
  if (size > maxFileBytes) return 'too_large';
  return null;
}

/** True when the buffer looks binary (NUL byte in the first 8 KB). */
export function looksBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

const LANG_BY_EXT: Record<string, string> = {
  js: 'JavaScript', mjs: 'JavaScript', cjs: 'JavaScript', jsx: 'JavaScript',
  ts: 'TypeScript', tsx: 'TypeScript', mts: 'TypeScript', cts: 'TypeScript',
  py: 'Python', pyi: 'Python', ipynb: 'Jupyter Notebook',
  go: 'Go', rs: 'Rust', java: 'Java', kt: 'Kotlin', kts: 'Kotlin', scala: 'Scala', groovy: 'Groovy',
  rb: 'Ruby', php: 'PHP', cs: 'C#', fs: 'F#', vb: 'Visual Basic',
  c: 'C', h: 'C', cc: 'C++', cpp: 'C++', cxx: 'C++', hpp: 'C++', hh: 'C++', m: 'Objective-C', mm: 'Objective-C',
  swift: 'Swift', dart: 'Dart', lua: 'Lua', r: 'R', jl: 'Julia', ex: 'Elixir', exs: 'Elixir', erl: 'Erlang',
  hs: 'Haskell', clj: 'Clojure', zig: 'Zig', nim: 'Nim', sol: 'Solidity',
  sh: 'Shell', bash: 'Shell', zsh: 'Shell', ps1: 'PowerShell', bat: 'Batchfile', cmd: 'Batchfile',
  html: 'HTML', htm: 'HTML', css: 'CSS', scss: 'SCSS', sass: 'SCSS', less: 'Less',
  vue: 'Vue', svelte: 'Svelte', astro: 'Astro',
  sql: 'SQL', graphql: 'GraphQL', gql: 'GraphQL', proto: 'Protocol Buffers',
  tf: 'HCL', hcl: 'HCL', nix: 'Nix',
};

/** Language name for a source file, or undefined for data/docs/config. */
export function languageOf(p: string): string | undefined {
  const b = baseName(p);
  if (b === 'Dockerfile' || b.endsWith('.Dockerfile') || /^Dockerfile\./.test(b)) return 'Dockerfile';
  if (b === 'Makefile' || b === 'makefile' || b === 'GNUmakefile') return 'Makefile';
  return LANG_BY_EXT[extension(p)];
}

export function isDockerfile(p: string): boolean {
  const b = baseName(p);
  return b === 'Dockerfile' || b === 'Containerfile' || /^Dockerfile\.[A-Za-z0-9_.-]+$/.test(b) || b.endsWith('.Dockerfile');
}

export function isComposeFile(p: string): boolean {
  return /^(docker-)?compose(\.[A-Za-z0-9_-]+)?\.ya?ml$/.test(baseName(p));
}

export type CiProvider = 'GitHub Actions' | 'GitLab CI' | 'CircleCI' | 'Travis CI' | 'Azure Pipelines' | 'Jenkins' | 'Bitbucket Pipelines' | 'Buildkite' | 'Drone';

export function ciProviderOf(p: string): CiProvider | undefined {
  if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(p)) return 'GitHub Actions';
  if (p === '.gitlab-ci.yml') return 'GitLab CI';
  if (p === '.circleci/config.yml') return 'CircleCI';
  if (p === '.travis.yml') return 'Travis CI';
  if (p === 'azure-pipelines.yml') return 'Azure Pipelines';
  if (p === 'Jenkinsfile') return 'Jenkins';
  if (p === 'bitbucket-pipelines.yml') return 'Bitbucket Pipelines';
  if (/^\.buildkite\/pipeline\.ya?ml$/.test(p)) return 'Buildkite';
  if (p === '.drone.yml') return 'Drone';
  return undefined;
}

export function isEnvExample(p: string): boolean {
  return /^\.env(\.[A-Za-z0-9_-]+)?\.(example|sample|template|dist|defaults)$/.test(baseName(p)) || /^(example|sample)\.env$/.test(baseName(p)) || baseName(p) === '.env.example';
}

/** A real .env file committed to the repository (not an example). */
export function isCommittedEnvFile(p: string): boolean {
  const b = baseName(p);
  return /^\.env(\.(local|development|dev|production|prod|staging|test))?$/.test(b);
}

export function isTestPath(p: string): boolean {
  return /(^|\/)(tests?|__tests__|spec|specs)\//.test(p) || /(\.|_)(test|spec)\.[a-z]+$/.test(p) || /(^|\/)test_[^/]+\.py$/.test(p);
}

const SECONDARY_EXT = new Set(['md', 'mdx', 'rst', 'txt', 'json', 'jsonl', 'ndjson', 'csv', 'tsv', 'xml', 'svg', 'html', 'htm', 'log', 'snap', 'po', 'pot', 'ipynb', 'geojson']);
const MANIFEST_NAMES = new Set(['package.json', 'composer.json', 'tsconfig.json', 'deno.json', 'app.json', 'vercel.json', 'netlify.toml', 'requirements.txt', 'index.html']);

/**
 * Lower-priority text for the analysis budget: documentation, data and test
 * fixtures. Source code, manifests, lockfiles and configuration come first.
 */
export function isSecondaryText(p: string): boolean {
  const b = baseName(p);
  if (MANIFEST_NAMES.has(b) || isLockfile(p) || /^\.env/.test(b) || /^requirements.*\.txt$/.test(b)) return false;
  if (/(^|\/)(docs?|documentation|examples?|samples?|fixtures?|testdata|__snapshots__|data|datasets?|i18n|locales?|translations?)\//i.test(p)) return true;
  return SECONDARY_EXT.has(extension(p));
}
