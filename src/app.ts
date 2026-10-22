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
import { RateLimiter } from './http/ratelimit.ts';
import {
  HttpError, securityHeaders, sendJson, sendError, readJsonBody, onlyKeys, ensureSession, clientIp, checkOrigin,
} from './http/util.ts';
import type { FixtureGitHubClient } from './demo/fixtures.ts';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export interface AppDeps {
  config: Config;
  github: GitHubClient;
  runner: Runner;
  log?: (msg: string) => void;
}

export interface App {
  server: http.Server;
  manager: RunManager;
  inspections: InspectionStore;
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
  const index = read('index.html').toString('utf8').replaceAll('{{PRODUCT_NAME}}', escapeHtml(productName));
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
  };
}

export function createApp(deps: AppDeps): App {
  const { config, github, runner } = deps;
  const log = deps.log ?? ((m: string) => console.log(m));
  const statics = loadStatic(config.productName);
  const inspections = new InspectionStore({ ttlSec: config.limits.inspectionRetentionSec });
  const manager = new RunManager({ runner, limits: config.limits, secretValues: config.secretValues });
  const inspector = new InspectService({ github, store: inspections, limits: config.limits, goImage: config.runner.images.go });

  const apiLimiter = new RateLimiter(300, 60_000);
  const inspectLimiter = new RateLimiter(config.limits.inspectionsPerIpPer10Min, 600_000);
  const runLimiter = new RateLimiter(config.limits.runsPerIpPerHour, 3_600_000);
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
      onlyKeys(body, ['inspectionId', 'checkId', 'acknowledged']);
      if (!isId(body.inspectionId)) throw new HttpError(400, 'invalid_inspection', 'Missing or invalid inspection id.');
      const insp = inspections.get(body.inspectionId, sessionId);
      if (!insp) throw new HttpError(404, 'inspection_expired', 'That inspection has expired. Inspect the repository again.');
      // Only runs that are actually created count towards the per-IP quota.
      const wait = runLimiter.peek(ip);
      if (wait > 0) throw new HttpError(429, 'rate_limited', `Too many runs. Try again in ${wait} seconds.`, wait);
      const run = await manager.create({ sessionId, inspection: insp, checkId: body.checkId, acknowledged: body.acknowledged });
      runLimiter.take(ip);
      return sendJson(res, 201, { run });
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
          'Content-Disposition': `attachment; filename="reporadar-run-${id.slice(0, 8)}.log"`,
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
    securityHeaders(res);
    let url: URL;
    try {
      url = new URL(req.url ?? '/', 'http://localhost');
    } catch {
      res.writeHead(400).end();
      return;
    }
    try {
      if (url.pathname === '/healthz') return sendJson(res, 200, { ok: true });
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
      log(`[error] ${req.method} ${url.pathname}: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
      return sendError(res, new HttpError(500, 'internal', 'Something went wrong. Please try again.'));
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 20_000;

  const maintenance = setInterval(() => {
    manager.purge();
    inspections.purge();
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
    close: () =>
      new Promise<void>((resolve) => {
        clearInterval(maintenance);
        clearInterval(sweeper);
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}
