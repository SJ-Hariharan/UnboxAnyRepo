/**
 * HTTP application: static UI + JSON API + Server-Sent Events.
 * Trust boundary: everything from the request is untrusted; everything from
 * GitHub or the sandbox is untrusted. Secrets stay in this process.
 */
import http from 'node:http';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Config, Ecosystem } from './config.ts';
import type { GitHubClient } from './github/client.ts';
import type { Runner, RunnerStatus } from './runner/types.ts';
import { InspectionStore } from './runs/inspections.ts';
import type { Inspection } from './runs/inspections.ts';
import { RunManager, RunError } from './runs/manager.ts';
import type { RunEvent } from './runs/manager.ts';
import type { LogLine } from './runs/logs.ts';
import { InspectService, InspectError } from './inspect.ts';
import { isId } from './runs/ids.ts';
import { BRAND, slugify } from './brand.ts';
import { RateLimiter } from './http/ratelimit.ts';
import {
  HttpError, securityHeaders, sendJson, sendError, readJsonBody, onlyKeys, ensureSession, clientIp, checkOrigin,
} from './http/util.ts';
import type { FixtureGitHubClient } from './demo/fixtures.ts';
import type { Transport } from './github/fetcher.ts';
import { PreviewStore, PreviewError, filesFromTar, previewHeaders, TOKEN_RE } from './preview/store.ts';
import { markdownReport, jsonReport } from './report/report.ts';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export interface AppDeps {
  config: Config;
  github: GitHubClient;
  runner: Runner;
  log?: (msg: string) => void;
  /** Test hook: transport for OSV.dev requests. */
  osvTransport?: Transport;
}

export interface App {
  server: http.Server;
  manager: RunManager;
  inspections: InspectionStore;
  previews: PreviewStore;
  close(): Promise<void>;
}

const LIVE_EXAMPLES = [
  { url: 'https://github.com/expressjs/express', label: 'expressjs/express', language: 'JavaScript' },
  { url: 'https://github.com/spf13/cobra', label: 'spf13/cobra', language: 'Go' },
  { url: 'https://github.com/pallets/itsdangerous', label: 'pallets/itsdangerous', language: 'Python' },
  { url: 'https://github.com/dtolnay/itoa', label: 'dtolnay/itoa', language: 'Rust' },
];

const SUPPORTED: { ecosystem: Ecosystem; label: string; checks: string[] }[] = [
  { ecosystem: 'node', label: 'Node.js (npm)', checks: ['npm test', 'npm run build', 'npm run lint'] },
  { ecosystem: 'python', label: 'Python', checks: ['pytest', 'unittest discover'] },
  { ecosystem: 'go', label: 'Go modules', checks: ['go test ./...', 'go vet ./...', 'go build ./...'] },
  { ecosystem: 'rust', label: 'Rust (Cargo)', checks: ['cargo test', 'cargo build'] },
];

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}

function loadStatic(productName: string): Map<string, { type: string; body: Buffer }> {
  const read = (f: string) => readFileSync(path.join(ROOT, 'public', f));
  const index = read('index.html')
    .toString('utf8')
    .replaceAll('{{PRODUCT_NAME}}', escapeHtml(productName))
    .replaceAll('{{PRODUCT_TAGLINE}}', escapeHtml(BRAND.tagline))
    .replaceAll('{{PRODUCT_DESCRIPTION}}', escapeHtml(BRAND.description));
  return new Map([
    ['/', { type: 'text/html; charset=utf-8', body: Buffer.from(index) }],
    ['/app.js', { type: 'text/javascript; charset=utf-8', body: read('app.js') }],
    ['/styles.css', { type: 'text/css; charset=utf-8', body: read('styles.css') }],
    ['/favicon.svg', { type: 'image/svg+xml', body: read('favicon.svg') }],
  ]);
}

function publicRunner(s: RunnerStatus) {
  return {
    available: s.available,
    isolation: s.isolation,
    label: s.label,
    reason: s.reason,
    dependencyFetch: s.dependencyFetch,
    dependencyFetchReason: s.dependencyFetchReason,
    ecosystems: s.ecosystems,
    limits: s.limits,
  };
}

function inspectionView(insp: Inspection, status: RunnerStatus) {
  return {
    id: insp.id,
    demo: insp.demo,
    notice: insp.notice,
    repo: insp.repo,
    commit: { sha: insp.commitSha, source: insp.commitSource },
    source: insp.source,
    detection: {
      status: insp.detection.status,
      ecosystems: insp.detection.ecosystems,
      warnings: insp.detection.warnings,
      unsupportedSignals: insp.detection.unsupportedSignals,
    },
    checks: insp.detection.checks.map((c) => {
      let blockedReason: string | undefined;
      if (!c.available) blockedReason = c.unavailableReason;
      else if (!status.available) blockedReason = status.reason ?? 'Execution is unavailable.';
      else if (!status.ecosystems[c.ecosystem].available) blockedReason = status.ecosystems[c.ecosystem].reason ?? 'Not available on this sandbox host.';
      else if (c.installsDependencies && !status.dependencyFetch) blockedReason = status.dependencyFetchReason ?? 'Dependency download is unavailable.';
      return {
        id: c.id,
        ecosystem: c.ecosystem,
        title: c.title,
        summary: c.summary,
        executes: c.executes,
        repoScripts: c.repoScripts,
        notes: c.notes,
        installsDependencies: c.installsDependencies,
        steps: c.steps,
        detected: c.available,
        runnable: blockedReason === undefined,
        ...(blockedReason !== undefined ? { blockedReason } : {}),
      };
    }),
    runner: publicRunner(status),
    analysis: insp.analysis,
  };
}

export function createApp(deps: AppDeps): App {
  const { config, github, runner } = deps;
  const log = deps.log ?? ((m: string) => console.log(m));
  const statics = loadStatic(config.productName);
  const inspections = new InspectionStore({ ttlSec: config.limits.inspectionRetentionSec, maxBytes: config.limits.inspectionStoreBytes });
  const previews = new PreviewStore({ ttlSec: config.limits.previewTtlSec, maxBytes: config.limits.previewStoreBytes, perSession: config.limits.previewsPerSession });
  const manager = new RunManager({
    runner,
    limits: config.limits,
    secretValues: config.secretValues,
    // Build previews: the artifact is a tar produced inside the verified sandbox.
    onArtifact: async (run, artifact) => {
      const p = await previews.create({
        sessionId: run.sessionId,
        inspectionId: run.inspectionId,
        repo: run.repo.fullName,
        commitSha: run.commitSha,
        kind: 'build',
        root: run.dir,
        rebuild: () => filesFromTar(artifact, { gzip: false, prefix: '', maxBytes: config.limits.previewMaxBytes }),
      });
      return p.token;
    },
  });
  const inspector = new InspectService({
    github,
    store: inspections,
    limits: config.limits,
    goImage: config.runner.images.go,
    analysis: config.analysis,
    userAgent: config.userAgent,
    ...(deps.osvTransport ? { osvTransport: deps.osvTransport } : {}),
  });

  const apiLimiter = new RateLimiter(300, 60_000);
  const inspectLimiter = new RateLimiter(config.limits.inspectionsPerIpPer10Min, 600_000);
  const runLimiter = new RateLimiter(config.limits.runsPerIpPerHour, 3_600_000);
  const previewLimiter = new RateLimiter(20, 600_000);
  const previewDomain = config.preview.domain;
  const previewScheme = config.publicOrigin?.startsWith('https:') ? 'https' : 'http';
  // Origins allowed to embed a preview, and preview origins the UI may embed.
  const appOrigins = config.publicOrigin ?? 'http://localhost:* http://127.0.0.1:*';
  const frameSrc = previewDomain ? `${previewScheme}://*.${previewDomain}${config.publicOrigin ? '' : ':*'}` : '';

  /** Preview URLs: on its own origin when a preview domain is configured, else path-based. */
  const previewView = (v: ReturnType<PreviewStore['view']>, req: http.IncomingMessage) => {
    const port = /:(\d{1,5})$/.exec(String(req.headers.host ?? ''))?.[1];
    const hostUrl = previewDomain ? `${previewScheme}://${v.token}.${previewDomain}${port && !config.publicOrigin ? `:${port}` : ''}/` : undefined;
    return { ...v, url: hostUrl ?? v.url, pathUrl: v.url };
  };

  /** Token if this request is addressed to a preview host; 'invalid' for other names under the preview domain. */
  const previewHostToken = (req: http.IncomingMessage): string | undefined => {
    if (!previewDomain) return undefined;
    const host = String(req.headers.host ?? '').toLowerCase().replace(/:\d{1,5}$/, '');
    if (!host.endsWith(`.${previewDomain}`)) return undefined;
    const label = host.slice(0, -(previewDomain.length + 1));
    return TOKEN_RE.test(label) ? label : 'invalid';
  };
  const sseCount = new Map<string, number>();

  const limit = (limiter: RateLimiter, key: string, what: string) => {
    const wait = limiter.take(key);
    if (wait > 0) throw new HttpError(429, 'rate_limited', `Too many ${what}. Try again in ${wait} seconds.`, wait);
  };

  const demoRepos = github.kind === 'fixtures' ? (github as FixtureGitHubClient).list?.() ?? [] : [];

  async function handleApi(req: http.IncomingMessage, res: http.ServerResponse, url: URL, sessionId: string, ip: string): Promise<void> {
    const p = url.pathname;
    const m = req.method ?? 'GET';
    if (m !== 'GET' && m !== 'POST') throw new HttpError(405, 'method_not_allowed', 'Method not allowed.');
    if (m === 'POST') checkOrigin(req, config.publicOrigin);
    limit(apiLimiter, ip, 'requests');

    if (p === '/api/config' && m === 'GET') {
      const status = await runner.status();
      return sendJson(res, 200, {
        productName: config.productName,
        brand: { tagline: BRAND.tagline, description: BRAND.description, version: BRAND.version },
        features: {
          previews: config.preview.enabled,
          osv: config.analysis.osv,
          githubAdvisories: config.analysis.githubAdvisories,
          scanners: config.analysis.scanners,
        },
        demo: github.kind === 'fixtures',
        examples:
          github.kind === 'fixtures'
            ? demoRepos.map((r) => ({ url: r.htmlUrl, label: r.name, language: r.language, description: r.description }))
            : LIVE_EXAMPLES,
        supported: SUPPORTED,
        runner: publicRunner(status),
        limits: {
          archiveMaxMB: Math.round(config.limits.archiveMaxCompressedBytes / 1048576),
          unpackedMaxMB: Math.round(config.limits.archiveMaxUncompressedBytes / 1048576),
          maxFiles: config.limits.archiveMaxFiles,
          runRetentionMin: Math.round(config.limits.runRetentionSec / 60),
          inspectionRetentionMin: Math.round(config.limits.inspectionRetentionSec / 60),
        },
      });
    }

    if (p === '/api/inspect' && m === 'POST') {
      const body = await readJsonBody(req);
      onlyKeys(body, ['url']);
      limit(inspectLimiter, ip, 'inspections');
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), config.limits.fetchTimeoutMs * 3);
      // Abort upstream work if the client disconnects. Note: listen on the *response*;
      // an IncomingMessage emits 'close' as soon as its body has been read.
      res.on('close', () => {
        if (!res.writableFinished) controller.abort();
      });
      try {
        const insp = await inspector.inspect(body.url, sessionId, controller.signal);
        return sendJson(res, 200, inspectionView(insp, await runner.status()));
      } finally {
        clearTimeout(timer);
      }
    }

    if (p === '/api/runs' && m === 'GET') return sendJson(res, 200, { runs: manager.list(sessionId) });

    if (p === '/api/runs' && m === 'POST') {
      const body = await readJsonBody(req);
      onlyKeys(body, ['inspectionId', 'checkId', 'acknowledged', 'preview']);
      if (!isId(body.inspectionId)) throw new HttpError(400, 'invalid_inspection', 'Missing or invalid inspection id.');
      const insp = inspections.get(body.inspectionId, sessionId);
      if (!insp) throw new HttpError(404, 'inspection_expired', 'That inspection has expired. Inspect the repository again.');
      let preview: { dir: string; maxBytes: number } | undefined;
      if (body.preview !== undefined && body.preview !== false) {
        const plan = insp.analysis.launch.preview;
        if (body.preview !== true) throw new HttpError(400, 'invalid_preview', 'preview must be true or false.');
        if (!config.preview.enabled) throw new HttpError(409, 'previews_disabled', 'Previews are disabled on this deployment.');
        if (plan.kind !== 'build' || !plan.root || plan.buildCheckId !== body.checkId) {
          throw new HttpError(409, 'preview_not_supported', 'A build preview is not available for this check.');
        }
        preview = { dir: plan.root, maxBytes: config.limits.previewMaxBytes };
      }
      // Only runs that are actually created count towards the per-IP quota.
      const wait = runLimiter.peek(ip);
      if (wait > 0) throw new HttpError(429, 'rate_limited', `Too many runs. Try again in ${wait} seconds.`, wait);
      const run = await manager.create({ sessionId, inspection: insp, checkId: body.checkId, acknowledged: body.acknowledged, ...(preview ? { preview } : {}) });
      runLimiter.take(ip);
      return sendJson(res, 201, { run });
    }

    const report = /^\/api\/inspections\/([^/]+)\/report$/.exec(p);
    if (report && m === 'GET') {
      const id = report[1] as string;
      const insp = isId(id) ? inspections.get(id, sessionId) : undefined;
      if (!insp) throw new HttpError(404, 'inspection_expired', 'That inspection has expired. Inspect the repository again.');
      const format = url.searchParams.get('format') ?? 'md';
      const base = `${slugify(config.productName)}-${insp.repo.fullName.replace('/', '-')}-${insp.commitSha.slice(0, 7)}`.replace(/[^A-Za-z0-9._-]/g, '-');
      if (format === 'json') {
        const body = JSON.stringify(jsonReport(insp, config.productName), null, 2);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': `attachment; filename="${base}.json"`, 'Cache-Control': 'no-store' });
        res.end(body);
        return;
      }
      if (format !== 'md') throw new HttpError(400, 'invalid_format', 'format must be md or json.');
      res.writeHead(200, { 'Content-Type': 'text/markdown; charset=utf-8', 'Content-Disposition': `attachment; filename="${base}.md"`, 'Cache-Control': 'no-store' });
      res.end(markdownReport(insp, config.productName));
      return;
    }

    if (p === '/api/previews' && m === 'GET') return sendJson(res, 200, { previews: previews.list(sessionId).map((v) => previewView(v, req)) });
    if (p === '/api/previews' && m === 'POST') {
      const body = await readJsonBody(req);
      onlyKeys(body, ['inspectionId']);
      if (!config.preview.enabled) throw new HttpError(409, 'previews_disabled', 'Previews are disabled on this deployment.');
      if (!isId(body.inspectionId)) throw new HttpError(400, 'invalid_inspection', 'Missing or invalid inspection id.');
      const insp = inspections.get(body.inspectionId, sessionId);
      if (!insp) throw new HttpError(404, 'inspection_expired', 'That inspection has expired. Inspect the repository again.');
      const plan = insp.analysis.launch.preview;
      if (plan.kind !== 'static') {
        throw new HttpError(409, 'preview_not_supported', plan.kind === 'build' ? 'This project must be built first; start the build check with a preview instead.' : plan.reason);
      }
      limit(previewLimiter, ip, 'previews');
      const tar = insp.sanitizedTarGz;
      const prefix = plan.root ? `src/${plan.root}` : 'src';
      const created = await previews.create({
        sessionId,
        inspectionId: insp.id,
        repo: insp.repo.fullName,
        commitSha: insp.commitSha,
        kind: 'static',
        root: plan.root ?? '',
        rebuild: () => filesFromTar(tar, { gzip: true, prefix, maxBytes: config.limits.previewMaxBytes }),
      });
      return sendJson(res, 201, { preview: previewView(previews.view(created), req) });
    }
    const pv = /^\/api\/previews\/([^/]+)\/(stop|restart)$/.exec(p);
    if (pv && m === 'POST') {
      const token = pv[1] as string;
      const v = pv[2] === 'stop' ? previews.stop(token, sessionId) : await previews.restart(token, sessionId);
      if (!v) throw new HttpError(404, 'not_found', 'Preview not found.');
      return sendJson(res, 200, { preview: previewView(v, req) });
    }

    const match = /^\/api\/runs\/([^/]+)(?:\/(log|events|cancel))?$/.exec(p);
    if (match) {
      const id = match[1] as string;
      const action = match[2];
      if (!isId(id)) throw new HttpError(404, 'not_found', 'Run not found.');
      if (action === undefined && m === 'GET') {
        const run = manager.get(id, sessionId);
        if (!run) throw new HttpError(404, 'not_found', 'Run not found.');
        return sendJson(res, 200, { run, lines: manager.logLines(id, sessionId) ?? [] });
      }
      if (action === 'log' && m === 'GET') {
        const text = manager.logText(id, sessionId);
        if (text === undefined) throw new HttpError(404, 'not_found', 'Run not found.');
        res.writeHead(200, {
          'Content-Type': 'text/plain; charset=utf-8',
          'Content-Disposition': `attachment; filename="${slugify(config.productName)}-run-${id.slice(0, 8)}.log"`,
          'Cache-Control': 'no-store',
        });
        res.end(text);
        return;
      }
      if (action === 'cancel' && m === 'POST') {
        const run = manager.cancel(id, sessionId);
        if (!run) throw new HttpError(404, 'not_found', 'Run not found.');
        return sendJson(res, 202, { run });
      }
      if (action === 'events' && m === 'GET') return streamEvents(req, res, id, sessionId, url);
    }
    throw new HttpError(404, 'not_found', 'Not found.');
  }

  function streamEvents(req: http.IncomingMessage, res: http.ServerResponse, id: string, sessionId: string, url: URL): void {
    const run = manager.get(id, sessionId);
    if (!run) throw new HttpError(404, 'not_found', 'Run not found.');
    const open = sseCount.get(sessionId) ?? 0;
    if (open >= 4) throw new HttpError(429, 'too_many_streams', 'Too many open log streams.', 5);
    sseCount.set(sessionId, open + 1);

    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-store',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    const lastIdHeader = req.headers['last-event-id'];
    const afterRaw = typeof lastIdHeader === 'string' ? lastIdHeader : (url.searchParams.get('after') ?? '0');
    const after = /^\d{1,9}$/.test(afterRaw) ? Number(afterRaw) : 0;
    const send = (event: string, data: unknown, eventId?: number) => {
      res.write(`${eventId !== undefined ? `id: ${eventId}\n` : ''}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    let pending: LogLine[] = [];
    let closed = false;
    const flush = () => {
      if (pending.length === 0 || closed) return;
      const batch = pending;
      pending = [];
      send('log', { lines: batch }, batch.at(-1)?.seq);
    };
    const flushTimer = setInterval(flush, 150);
    const heartbeat = setInterval(() => !closed && res.write(': keep-alive\n\n'), 15_000);
    let unsubscribe: (() => void) | undefined;
    const close = () => {
      if (closed) return;
      flush();
      closed = true;
      clearInterval(flushTimer);
      clearInterval(heartbeat);
      unsubscribe?.();
      const left = (sseCount.get(sessionId) ?? 1) - 1;
      if (left > 0) sseCount.set(sessionId, left);
      else sseCount.delete(sessionId);
      res.end();
    };
    res.on('close', close); // client disconnected (or we ended the stream)

    send('state', { run });
    if (run.terminal) {
      send('log', { lines: manager.logLines(id, sessionId) ?? [], final: true });
      send('end', { run });
      close();
      return;
    }
    const backlog = manager.logLines(id, sessionId, after) ?? [];
    if (backlog.length > 0) send('log', { lines: backlog }, backlog.at(-1)?.seq);
    if (run.log.truncated) send('truncated', {});

    unsubscribe = manager.subscribe(id, sessionId, (e: RunEvent) => {
      if (closed) return;
      if (e.type === 'log') {
        pending.push(...e.lines);
        if (pending.length >= 200) flush();
      } else if (e.type === 'truncated') {
        flush();
        send('truncated', {});
      } else {
        flush();
        send('state', { run: e.run });
        if (e.run.terminal) {
          send('log', { lines: manager.logLines(id, sessionId) ?? [], final: true });
          send('end', { run: e.run });
          close();
        }
      }
    });
  }

  const server = http.createServer(async (req, res) => {
    securityHeaders(res, frameSrc);
    let url: URL;
    try {
      url = new URL(req.url ?? '/', 'http://localhost');
    } catch {
      res.writeHead(400).end();
      return;
    }
    try {
      // A preview host serves only that preview's files, at its root: never the app or the API.
      const hostToken = previewHostToken(req);
      if (hostToken !== undefined) return servePreviewFiles(req, res, hostToken, url.pathname, '', appOrigins);
      if (url.pathname === '/healthz') return sendJson(res, 200, { ok: true });
      if (url.pathname.startsWith('/preview/')) return servePreview(req, res, url);
      // A previewed page that uses absolute paths (/assets/app.js, /api/data.json) asks for
      // them at the site root. Send those into the preview; never to this app's API or UI.
      const fromPreview = req.method === 'GET' || req.method === 'HEAD' ? previewReferrer(req) : undefined;
      if (fromPreview) {
        // The redirect is fetched from the preview's opaque origin: it needs the preview's cross-origin headers.
        res.writeHead(307, { ...previewHeaders('text/plain; charset=utf-8'), Location: `/preview/${fromPreview}${url.pathname}${url.search}` });
        res.end();
        return;
      }
      if (url.pathname.startsWith('/api/')) {
        const sessionId = ensureSession(req, res, config.secureCookies);
        const ip = clientIp(req, config.trustProxy);
        await handleApi(req, res, url, sessionId, ip);
        return;
      }
      const asset = statics.get(url.pathname);
      if (asset && (req.method === 'GET' || req.method === 'HEAD')) {
        if (url.pathname === '/') ensureSession(req, res, config.secureCookies);
        res.writeHead(200, {
          'Content-Type': asset.type,
          'Content-Length': asset.body.length,
          'Cache-Control': url.pathname === '/' ? 'no-store' : 'no-cache',
        });
        res.end(req.method === 'HEAD' ? undefined : asset.body);
        return;
      }
      throw new HttpError(404, 'not_found', 'Not found.');
    } catch (err) {
      if (res.headersSent) {
        res.end();
        return;
      }
      if (err instanceof HttpError) return sendError(res, err);
      if (err instanceof InspectError) return sendError(res, new HttpError(err.status, err.code, err.message, err.retryAfterSec));
      if (err instanceof RunError) return sendError(res, new HttpError(err.status, err.code, err.message));
      if (err instanceof PreviewError) return sendError(res, new HttpError(err.status, err.code, err.message));
      log(`[error] ${req.method} ${url.pathname}: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
      return sendError(res, new HttpError(500, 'internal', 'Something went wrong. Please try again.'));
    }
  });
  /** Token of the preview a request came from, judged by its Referer, if that preview is running. */
  function previewReferrer(req: http.IncomingMessage): string | undefined {
    const ref = req.headers.referer;
    if (typeof ref !== 'string') return undefined;
    let u: URL;
    try {
      u = new URL(ref);
    } catch {
      return undefined;
    }
    if (u.host !== req.headers.host) return undefined;
    const t = /^\/preview\/([a-f0-9]{32})\//.exec(u.pathname)?.[1];
    return t && previews.serve(t) ? t : undefined;
  }

  function servePreview(req: http.IncomingMessage, res: http.ServerResponse, url: URL): void {
    const m = /^\/preview\/([^/]+)(\/.*)?$/.exec(url.pathname);
    const token = m?.[1] ?? '';
    if (m?.[2] === undefined && TOKEN_RE.test(token) && previews.serve(token)) {
      res.writeHead(308, { Location: `/preview/${token}/`, 'Cache-Control': 'no-store' });
      res.end();
      return;
    }
    servePreviewFiles(req, res, token, m?.[2] ?? '/', `/preview/${token}`, "'self'");
  }

  /** Serve one preview's file. `base` is '' on a preview host, or /preview/<token> for path-based URLs. */
  function servePreviewFiles(req: http.IncomingMessage, res: http.ServerResponse, token: string, pathname: string, base: string, ancestors: string): void {
    res.removeHeader('X-Frame-Options');
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, previewHeaders('text/plain; charset=utf-8', ancestors));
      res.end();
      return;
    }
    const preview = TOKEN_RE.test(token) ? previews.serve(token) : undefined;
    const notFound = (msg: string) => {
      const body = Buffer.from(msg);
      res.writeHead(404, { ...previewHeaders('text/plain; charset=utf-8', ancestors), 'Content-Length': body.length });
      res.end(req.method === 'HEAD' ? undefined : body);
    };
    if (!preview) return notFound('This preview does not exist, was stopped, or has expired.');
    // Decode each segment, then re-validate: no "..", no control characters, no backslashes.
    let rel = '';
    try {
      const segs = pathname.split('/').slice(1).map((x) => decodeURIComponent(x));
      if (segs.some((x) => x === '..' || x === '.' || x.includes('\\') || x.includes('\0') || /[\x00-\x1f]/.test(x))) return notFound('Not found.');
      rel = segs.join('/');
    } catch {
      return notFound('Not found.');
    }
    const tryPaths = rel === '' || rel.endsWith('/') ? [`${rel}index.html`] : [rel, `${rel}.html`];
    let file = tryPaths.map((x) => preview.files.get(x)).find((f) => f !== undefined);
    if (!file && preview.files.has(`${rel}/index.html`)) {
      res.writeHead(308, { Location: `${base}${pathname}/`, 'Cache-Control': 'no-store' });
      res.end();
      return;
    }
    // Single-page apps: navigations to unknown routes get the entry page.
    if (!file && !/\.[A-Za-z0-9]{1,8}$/.test(rel) && (req.headers['sec-fetch-mode'] === 'navigate' || /text\/html/.test(String(req.headers.accept ?? '')))) {
      file = preview.files.get('index.html');
    }
    if (!file) return notFound('Not found in this preview.');
    res.writeHead(200, { ...previewHeaders(file.type, ancestors), 'Content-Length': file.data.length });
    res.end(req.method === 'HEAD' ? undefined : file.data);
  }

  server.requestTimeout = 30_000;
  server.headersTimeout = 20_000;

  const maintenance = setInterval(() => {
    manager.purge();
    inspections.purge();
    previews.purge();
    previewLimiter.purge();
    apiLimiter.purge();
    inspectLimiter.purge();
    runLimiter.purge();
  }, 60_000);
  maintenance.unref();
  const sweeper = setInterval(() => void runner.sweep?.().catch(() => {}), 5 * 60_000);
  sweeper.unref();
  void runner.sweep?.().catch(() => {});

  return {
    server,
    manager,
    inspections,
    previews,
    close: () =>
      new Promise<void>((resolve) => {
        clearInterval(maintenance);
        clearInterval(sweeper);
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}
