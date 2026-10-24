/**
 * Live previews of static web output.
 *
 * Files come only from (a) the sanitized repository snapshot or (b) the
 * output of a build that ran in the verified sandbox. They are held in memory
 * and served read-only under /preview/<token>/ — no repository process runs
 * on the server, and no host file is ever read.
 *
 * Isolation in the browser: preview responses carry
 *   Content-Security-Policy: sandbox allow-scripts ... (no allow-same-origin)
 * so the page runs in an opaque origin. It cannot read this site's cookies,
 * storage or API responses, and SameSite=Strict session cookies are not sent
 * with its requests. Tokens are 128-bit random capabilities that expire.
 */
import { randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import zlib from 'node:zlib';
import { readTar, TarError } from '../source/tar.ts';
import { validateRelativePath } from '../source/archive.ts';

export interface PreviewFile {
  data: Buffer;
  type: string;
}

export interface PreviewHealth {
  ok: boolean;
  checks: { name: string; ok: boolean; detail: string }[];
}

export interface Preview {
  token: string;
  sessionId: string;
  inspectionId: string;
  repo: string;
  commitSha: string;
  kind: 'static' | 'build';
  root: string;
  files: Map<string, PreviewFile>;
  bytes: number;
  createdAt: number;
  expiresAt: number;
  stopped: boolean;
  health: PreviewHealth;
  /** Kept so a stopped preview can be restarted without re-inspecting. */
  rebuild: () => Promise<Map<string, PreviewFile>>;
}

export interface PreviewView {
  token: string;
  url: string;
  repo: string;
  commitSha: string;
  kind: 'static' | 'build';
  root: string;
  state: 'running' | 'stopped' | 'expired';
  files: number;
  bytes: number;
  createdAt: string;
  expiresAt: string;
  health: PreviewHealth;
}

export class PreviewError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, status: number, message: string) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export const TOKEN_RE = /^[a-f0-9]{32}$/;
const MAX_FILES = 5000;

const TYPES: Record<string, string> = {
  html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8',
  js: 'text/javascript; charset=utf-8', mjs: 'text/javascript; charset=utf-8', cjs: 'text/javascript; charset=utf-8',
  json: 'application/json; charset=utf-8', map: 'application/json; charset=utf-8', webmanifest: 'application/manifest+json',
  txt: 'text/plain; charset=utf-8', md: 'text/plain; charset=utf-8', xml: 'application/xml', csv: 'text/csv; charset=utf-8',
  svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', avif: 'image/avif', ico: 'image/x-icon', bmp: 'image/bmp',
  woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf', otf: 'font/otf',
  mp3: 'audio/mpeg', wav: 'audio/wav', ogg: 'audio/ogg', mp4: 'video/mp4', webm: 'video/webm',
  wasm: 'application/wasm', pdf: 'application/pdf',
};

export function contentType(path: string): string {
  const ext = path.slice(path.lastIndexOf('.') + 1).toLowerCase();
  return Object.hasOwn(TYPES, ext) ? (TYPES[ext] as string) : 'application/octet-stream';
}

/**
 * Collect files under `prefix` from a tar stream (our own sanitized snapshot
 * or a sandbox build artifact), re-validating every path and bounding size.
 */
export async function filesFromTar(tar: Buffer, opts: { gzip: boolean; prefix: string; maxBytes: number }): Promise<Map<string, PreviewFile>> {
  const files = new Map<string, PreviewFile>();
  let total = 0;
  const prefix = opts.prefix === '' ? '' : `${opts.prefix.replace(/\/+$/, '')}/`;
  const stream = opts.gzip ? Readable.from([tar]).pipe(zlib.createGunzip()) : Readable.from([tar]);
  const tooLarge = () => new PreviewError('too_large', 413, `The site is larger than the ${Math.round(opts.maxBytes / 1048576)} MB preview limit.`);
  try {
  await readTar(stream as AsyncIterable<Buffer>, { maxFileBytes: opts.maxBytes, maxMetaBytes: 256 * 1024 }, async ({ entry, data }) => {
    if (entry.kind !== 'file') return;
    const raw = entry.path.replace(/^\.\//, '');
    if (!raw.startsWith(prefix)) return;
    const rel = raw.slice(prefix.length);
    if (rel === '') return;
    let safe: string;
    try {
      safe = validateRelativePath(rel);
    } catch {
      throw new PreviewError('unsafe_output', 422, 'The output contains a file path that is not allowed.');
    }
    const body = data ?? Buffer.alloc(0);
    total += body.length;
    if (total > opts.maxBytes) throw tooLarge();
    if (files.size >= MAX_FILES) throw new PreviewError('too_many_files', 413, `The site has more than ${MAX_FILES} files.`);
    files.set(safe, { data: body, type: contentType(safe) });
  });
  } catch (err) {
    if (err instanceof PreviewError) throw err;
    if (err instanceof TarError && err.code === 'file_too_large') throw tooLarge();
    throw new PreviewError('unreadable_output', 422, 'The site files could not be read.');
  }
  return files;
}

/** Health checks: an entry page exists and is HTML; local references resolve. */
export function checkHealth(files: Map<string, PreviewFile>): PreviewHealth {
  const checks: PreviewHealth['checks'] = [];
  const index = files.get('index.html');
  checks.push({ name: 'Entry page', ok: index !== undefined, detail: index ? 'index.html is present' : 'No index.html at the preview root' });
  if (index) {
    const html = index.data.toString('utf8', 0, Math.min(index.data.length, 512 * 1024));
    const looksHtml = /<(!doctype html|html|head|body|script|div|main)\b/i.test(html);
    checks.push({ name: 'HTML document', ok: looksHtml, detail: looksHtml ? 'index.html parses as an HTML page' : 'index.html does not look like HTML' });
    const refs = [...html.matchAll(/\b(?:src|href)\s*=\s*["']([^"'#?]+)/gi)].map((m) => m[1] as string).filter((u) => !/^(?:[a-z][a-z0-9+.-]*:|\/\/|data:|#|mailto:)/i.test(u));
    const missing: string[] = [];
    let absolute = 0;
    for (const ref of refs.slice(0, 200)) {
      const p = ref.startsWith('/') ? ref.slice(1) : ref.replace(/^\.\//, '');
      if (ref.startsWith('/')) absolute++;
      let decoded = p;
      try {
        decoded = decodeURIComponent(p);
      } catch {
        /* keep raw */
      }
      if (decoded === '' || files.has(decoded) || files.has(`${decoded.replace(/\/$/, '')}/index.html`)) continue;
      if (!missing.includes(decoded)) missing.push(decoded);
    }
    if (refs.length) {
      checks.push({
        name: 'Local files referenced by index.html',
        ok: missing.length === 0,
        detail: missing.length === 0 ? `All ${refs.length} local references resolve` : `${missing.length} missing: ${missing.slice(0, 5).join(', ')}${missing.length > 5 ? ', …' : ''} (often produced by a build step)`,
      });
    }
    if (absolute > 0) checks.push({ name: 'Absolute paths', ok: true, detail: `${absolute} reference(s) start with "/"; they load from the preview's own address (the alternative path-based link may miss them)` });
  }
  return { ok: checks.every((c) => c.ok), checks };
}

export class PreviewStore {
  private readonly items = new Map<string, Preview>();
  private readonly ttlMs: number;
  private readonly maxBytes: number;
  private readonly perSession: number;

  constructor(opts: { ttlSec: number; maxBytes: number; perSession: number }) {
    this.ttlMs = opts.ttlSec * 1000;
    this.maxBytes = opts.maxBytes;
    this.perSession = opts.perSession;
  }

  async create(input: Omit<Preview, 'token' | 'files' | 'bytes' | 'createdAt' | 'expiresAt' | 'stopped' | 'health'>): Promise<Preview> {
    const active = [...this.items.values()].filter((p) => p.sessionId === input.sessionId && this.isLive(p));
    if (active.length >= this.perSession) {
      // Replace the oldest of this session's previews rather than refusing.
      const oldest = active.sort((a, b) => a.createdAt - b.createdAt)[0] as Preview;
      this.items.delete(oldest.token);
    }
    const files = await input.rebuild();
    const preview: Preview = {
      ...input,
      token: randomBytes(16).toString('hex'),
      files,
      bytes: [...files.values()].reduce((n, f) => n + f.data.length, 0),
      createdAt: Date.now(),
      expiresAt: Date.now() + this.ttlMs,
      stopped: false,
      health: checkHealth(files),
    };
    this.items.set(preview.token, preview);
    this.evict();
    return preview;
  }

  private isLive(p: Preview): boolean {
    return !p.stopped && Date.now() < p.expiresAt;
  }

  /** For serving: only running previews, by capability token. */
  serve(token: string): Preview | undefined {
    if (!TOKEN_RE.test(token)) return undefined;
    const p = this.items.get(token);
    return p && this.isLive(p) ? p : undefined;
  }

  owned(token: string, sessionId: string): Preview | undefined {
    if (!TOKEN_RE.test(token)) return undefined;
    const p = this.items.get(token);
    return p && p.sessionId === sessionId ? p : undefined;
  }

  list(sessionId: string): PreviewView[] {
    return [...this.items.values()].filter((p) => p.sessionId === sessionId).sort((a, b) => b.createdAt - a.createdAt).map((p) => this.view(p));
  }

  stop(token: string, sessionId: string): PreviewView | undefined {
    const p = this.owned(token, sessionId);
    if (!p) return undefined;
    p.stopped = true;
    p.files = new Map(); // release memory; restart rebuilds from the source
    p.bytes = 0;
    return this.view(p);
  }

  async restart(token: string, sessionId: string): Promise<PreviewView | undefined> {
    const p = this.owned(token, sessionId);
    if (!p) return undefined;
    p.files = await p.rebuild();
    p.bytes = [...p.files.values()].reduce((n, f) => n + f.data.length, 0);
    p.health = checkHealth(p.files);
    p.stopped = false;
    p.expiresAt = Date.now() + this.ttlMs;
    this.evict();
    return this.view(p);
  }

  view(p: Preview): PreviewView {
    return {
      token: p.token,
      url: `/preview/${p.token}/`,
      repo: p.repo,
      commitSha: p.commitSha,
      kind: p.kind,
      root: p.root,
      state: p.stopped ? 'stopped' : Date.now() >= p.expiresAt ? 'expired' : 'running',
      files: p.files.size,
      bytes: p.bytes,
      createdAt: new Date(p.createdAt).toISOString(),
      expiresAt: new Date(p.expiresAt).toISOString(),
      health: p.health,
    };
  }

  /** Drop expired previews (after a grace period so the owner sees "expired"), and enforce the memory cap. */
  purge(): void {
    const now = Date.now();
    for (const [t, p] of this.items) {
      if (now >= p.expiresAt) {
        p.files = new Map();
        p.bytes = 0;
      }
      if (now >= p.expiresAt + this.ttlMs) this.items.delete(t);
    }
    this.evict();
  }

  private evict(): void {
    let total = 0;
    for (const p of this.items.values()) total += p.bytes;
    for (const [t, p] of this.items) {
      if (total <= this.maxBytes) break;
      total -= p.bytes;
      this.items.delete(t);
    }
  }

  get size(): number {
    return this.items.size;
  }
}

/**
 * Response headers for preview content. `frameAncestors` lists the app
 * origin(s) allowed to embed the preview (default: same origin only).
 */
export function previewHeaders(type: string, frameAncestors = "'self'"): Record<string, string> {
  return {
    'Content-Type': type,
    // Opaque origin: no allow-same-origin. The page cannot read this site's cookies, storage or API.
    'Content-Security-Policy': `sandbox allow-scripts allow-forms allow-popups allow-modals allow-downloads allow-pointer-lock; default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval'; connect-src 'self' https: wss:; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors ${frameAncestors}`,
    'X-Content-Type-Options': 'nosniff',
    // Requests from the opaque origin are cross-origin; allow the page's own assets to load.
    'Access-Control-Allow-Origin': '*',
    'Cross-Origin-Resource-Policy': 'cross-origin',
    // Full URL on same-scheme requests so absolute asset paths can be redirected into the preview.
    'Referrer-Policy': 'no-referrer-when-downgrade',
    'Cache-Control': 'no-store',
    'X-Robots-Tag': 'noindex, nofollow',
  };
}
