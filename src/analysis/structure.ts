import type { SourceView } from './source.ts';
import type { StructureSummary, LanguageShare } from './types.ts';
import { languageOf, isVendored } from './paths.ts';

const ENTRY_CANDIDATES: [RegExp, string][] = [
  [/^index\.html$/, 'Static site entry page'],
  [/^(src\/)?(main|index|app|server)\.(js|mjs|cjs|ts|tsx|jsx)$/, 'Conventional JavaScript/TypeScript entry module'],
  [/^(app|main|wsgi|asgi|manage|run|server)\.py$/, 'Conventional Python entry module'],
  [/^[^/]+\/(wsgi|asgi)\.py$/, 'Python WSGI/ASGI application module'],
  [/^(src\/)?[^/]+\/__main__\.py$/, 'Python package entry point (python -m)'],
  [/^main\.go$/, 'Go main package'],
  [/^cmd\/[^/]+\/main\.go$/, 'Go command'],
  [/^src\/main\.rs$/, 'Rust binary crate'],
  [/^src\/bin\/[^/]+\.rs$/, 'Rust binary'],
  [/^(Dockerfile|Containerfile)$/, 'Container build definition'],
  [/^(docker-)?compose\.ya?ml$/, 'Multi-service definition'],
];

export function analyseStructure(src: SourceView, pkg: Record<string, unknown> | undefined): StructureSummary {
  const top = new Map<string, { kind: 'dir' | 'file'; files: number }>();
  const langs = new Map<string, { files: number; bytes: number }>();
  let codeBytes = 0;
  for (const f of src.files) {
    const first = f.path.split('/')[0] as string;
    const isDir = f.path.includes('/');
    const entry = top.get(first) ?? { kind: isDir ? 'dir' : 'file', files: 0 };
    entry.files++;
    top.set(first, entry);
    if (isVendored(f.path)) continue;
    const lang = languageOf(f.path);
    if (!lang) continue;
    const l = langs.get(lang) ?? { files: 0, bytes: 0 };
    l.files++;
    l.bytes += f.size;
    codeBytes += f.size;
    langs.set(lang, l);
  }
  const languages: LanguageShare[] = [...langs.entries()]
    .map(([name, v]) => ({ name, files: v.files, bytes: v.bytes, percent: codeBytes ? Math.round((v.bytes / codeBytes) * 1000) / 10 : 0 }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 12);

  const entryPoints: { path: string; reason: string }[] = [];
  const seen = new Set<string>();
  const add = (path: string, reason: string) => {
    if (seen.has(path) || entryPoints.length >= 12) return;
    seen.add(path);
    entryPoints.push({ path, reason });
  };
  if (pkg) {
    for (const key of ['main', 'module', 'browser'] as const) {
      const v = Object.hasOwn(pkg, key) ? pkg[key] : undefined;
      if (typeof v === 'string' && v.length < 200) add(v.replace(/^\.\//, ''), `package.json "${key}"`);
    }
    const bin = Object.hasOwn(pkg, 'bin') ? pkg.bin : undefined;
    if (typeof bin === 'string') add(bin.replace(/^\.\//, ''), 'package.json "bin"');
    else if (bin && typeof bin === 'object') {
      for (const [k, v] of Object.entries(bin as Record<string, unknown>).slice(0, 4)) {
        if (typeof v === 'string') add(v.replace(/^\.\//, ''), `package.json bin "${k.slice(0, 40)}"`);
      }
    }
  }
  for (const f of src.files) {
    if (isVendored(f.path)) continue;
    for (const [re, reason] of ENTRY_CANDIDATES) if (re.test(f.path)) add(f.path, reason);
  }
  // Python apps that construct a web app object at module level.
  for (const p of src.textPaths()) {
    if (!p.endsWith('.py') || p.split('/').length > 3 || isVendored(p)) continue;
    const t = src.text(p);
    if (t && /^\s*(app|application)\s*=\s*(Flask|FastAPI|Starlette|Sanic|Quart)\(/m.test(t)) add(p, 'Creates a web application object');
  }

  return {
    fileCount: src.files.length,
    dirCount: src.dirs.length,
    totalBytes: src.totalBytes,
    topLevel: [...top.entries()]
      .map(([name, v]) => ({ name, kind: v.kind, files: v.files }))
      .sort((a, b) => (a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === 'dir' ? -1 : 1))
      .slice(0, 40),
    languages,
    // A package.json entry that is not in the repository is usually build output.
    entryPoints: entryPoints.map((e) => (src.has(e.path) ? e : { path: e.path, reason: `${e.reason} (not in the repository; probably produced by a build)` })),
  };
}
