import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, Client, DEMO } from '../helpers/server.ts';
import type { TestServer } from '../helpers/server.ts';
import { FakeRunner } from '../helpers/fake-runner.ts';
import { buildTar } from '../helpers/tarbuilder.ts';

let srv: TestServer;
let runner: FakeRunner;
before(async () => {
  runner = new FakeRunner();
  srv = await startServer({ runner });
});
after(async () => srv.close());

async function inspect(c: Client, name: string) {
  const r = await c.json('/api/inspect', { json: { url: DEMO(name) } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return r.data;
}

test('inspection returns the full analysis, pinned to the commit', async () => {
  const c = new Client(srv.base);
  const insp = await inspect(c, 'risky-node-api');
  const a = insp.analysis;
  assert.match(insp.commit.sha, /^[a-f0-9]{40}$/);
  assert.equal(a.launch.primary, 'node-server');
  assert.ok(a.findings.length >= 5);
  for (const f of a.findings) {
    assert.match(f.id, /^UAR-/);
    assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(f.severity));
    assert.ok(['confirmed', 'heuristic', 'informational', 'unverified'].includes(f.status));
    assert.ok(f.method && f.risk && f.remediation);
  }
  assert.ok(a.tools.some((t: { tool: string; state: string }) => t.tool === 'OSV.dev' && t.state === 'disabled'), 'offline demo does not pretend to have checked dependencies');
  assert.match(a.disclaimer, /cannot prove that code is safe/);
  const cfg = await c.json('/api/config');
  assert.equal(cfg.data.productName, 'UnboxAnyRepo');
  assert.match(cfg.data.brand.tagline, /From GitHub link to running project/);
  assert.equal(cfg.data.features.previews, true);
});

test('reports download as Markdown or JSON, only for the owning session', async () => {
  const c = new Client(srv.base);
  const insp = await inspect(c, 'flask-app');
  const md = await c.req(`/api/inspections/${insp.id}/report`);
  assert.equal(md.status, 200);
  assert.match(md.headers.get('content-type') ?? '', /text\/markdown/);
  assert.match(md.headers.get('content-disposition') ?? '', /attachment; filename="unboxanyrepo-unbox-demo-flask-app-[a-f0-9]{7}\.md"/);
  const text = await md.text();
  assert.ok(text.includes(insp.commit.sha));
  assert.match(text, /## Security findings/);
  assert.match(text, /## How to run it locally/);
  const js = await c.json(`/api/inspections/${insp.id}/report?format=json`);
  assert.equal(js.status, 200);
  assert.equal(js.data.schema, 'unboxanyrepo.report/v1');
  assert.equal(js.data.commit.sha, insp.commit.sha);
  assert.equal((await c.json(`/api/inspections/${insp.id}/report?format=html`)).status, 400);
  const other = new Client(srv.base);
  assert.equal((await other.json(`/api/inspections/${insp.id}/report`)).status, 404);
  assert.equal((await c.json('/api/inspections/nothex/report')).status, 404);
});

test('static preview: served from the snapshot in an opaque origin, with a capability URL', async () => {
  const c = new Client(srv.base);
  const insp = await inspect(c, 'static-site');
  assert.equal(insp.analysis.launch.preview.kind, 'static');
  const created = await c.json('/api/previews', { json: { inspectionId: insp.id } });
  assert.equal(created.status, 201, JSON.stringify(created.data));
  const p = created.data.preview;
  // Served on its own origin (a different site from the app) with a path-based fallback.
  assert.equal(p.url, `http://${p.token}.preview.localhost:${new URL(srv.base).port}/`);
  assert.match(p.pathUrl, /^\/preview\/[a-f0-9]{32}\/$/);
  p.url = p.pathUrl;
  assert.equal(p.state, 'running');
  assert.equal(p.health.ok, true, JSON.stringify(p.health));

  const page = await fetch(srv.base + p.url);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Tiny Tip Calculator/);
  const csp = page.headers.get('content-security-policy') ?? '';
  assert.match(csp, /^sandbox /);
  assert.doesNotMatch(csp, /allow-same-origin/);
  assert.equal(page.headers.get('set-cookie'), null, 'previews never receive or set the session cookie');
  assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
  assert.match((await fetch(`${srv.base}${p.url}style.css`)).headers.get('content-type') ?? '', /text\/css/);
  assert.equal((await fetch(`${srv.base}${p.url}about`, { redirect: 'manual' })).status, 308);
  assert.equal((await fetch(`${srv.base}${p.url}about/`)).status, 200);
  for (const bad of ['%2e%2e/%2e%2e/package.json', '..%2Fpackage.json', 'a%00b', '%5c..%5cpackage.json', 'nope.js']) {
    assert.equal((await fetch(`${srv.base}${p.url}${bad}`)).status, 404, bad);
  }
  // Absolute paths requested by the preview page are sent into the preview, never to the app.
  const viaRef = await fetch(`${srv.base}/img/logo.svg`, { redirect: 'manual', headers: { referer: `${srv.base}${p.url}` } });
  assert.equal(viaRef.status, 307);
  assert.equal(viaRef.headers.get('location'), `${p.url}img/logo.svg`);
  const apiViaRef = await fetch(`${srv.base}/api/config`, { redirect: 'manual', headers: { referer: `${srv.base}${p.url}` } });
  assert.equal(apiViaRef.status, 307, 'API is not reachable from preview pages');
  assert.equal((await fetch(`${srv.base}/preview/${'0'.repeat(32)}/`)).status, 404);

  // Only the owner can manage it; stop makes it unreachable; restart brings it back.
  const other = new Client(srv.base);
  assert.equal((await other.json(`/api/previews/${p.token}/stop`, { json: {} })).status, 404);
  assert.equal((await other.json('/api/previews')).data.previews.length, 0);
  assert.equal((await c.json(`/api/previews/${p.token}/stop`, { json: {} })).data.preview.state, 'stopped');
  assert.equal((await fetch(srv.base + p.url)).status, 404);
  assert.equal((await c.json(`/api/previews/${p.token}/restart`, { json: {} })).data.preview.state, 'running');
  assert.equal((await fetch(srv.base + p.url)).status, 200);
  assert.equal((await c.json('/api/previews')).data.previews.length, 1);
});

test('previews are refused for projects that need a server or a build', async () => {
  const c = new Client(srv.base);
  const api = await inspect(c, 'risky-node-api');
  const r = await c.json('/api/previews', { json: { inspectionId: api.id } });
  assert.equal(r.status, 409);
  assert.match(r.data.error.message, /not supported/);
  const vite = await inspect(c, 'vite-app');
  const v = await c.json('/api/previews', { json: { inspectionId: vite.id } });
  assert.equal(v.status, 409);
  assert.match(v.data.error.message, /built first/);
  assert.equal((await c.json('/api/previews', { json: { inspectionId: vite.id, extra: 1 } })).status, 400);
});

test('build preview: output collected from the (scripted) sandbox run is served as a preview', async () => {
  runner.script = { lines: ['vite build\n'], artifact: buildTar([{ name: './index.html', data: '<!doctype html><title>Built</title><script type="module" src="/assets/app.js"></script>' }, { name: './assets/app.js', data: 'console.log(1)' }]) };
  const c = new Client(srv.base);
  const insp = await inspect(c, 'vite-app');
  assert.equal(insp.analysis.launch.preview.buildCheckId, 'node.npm-build');
  const wrong = await c.json('/api/runs', { json: { inspectionId: insp.id, checkId: 'node.npm-test', acknowledged: true, preview: true } });
  assert.equal(wrong.status, 409);
  const r = await c.json('/api/runs', { json: { inspectionId: insp.id, checkId: 'node.npm-build', acknowledged: true, preview: true } });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  let run = r.data.run;
  for (let i = 0; i < 200 && !run.terminal; i++) {
    await new Promise((res) => setTimeout(res, 20));
    run = (await c.json(`/api/runs/${run.id}`)).data.run;
  }
  assert.equal(run.state, 'succeeded');
  assert.match(run.preview.token, /^[a-f0-9]{32}$/);
  assert.equal((await c.json('/api/previews')).data.previews[0].pathUrl, `/preview/${run.preview.token}/`);
  const page = await fetch(`${srv.base}/preview/${run.preview.token}/`);
  assert.match(await page.text(), /Built/);
  const asset = await fetch(`${srv.base}/assets/app.js`, { redirect: 'manual', headers: { referer: `${srv.base}/preview/${run.preview.token}/` } });
  assert.equal(asset.headers.get('location'), `/preview/${run.preview.token}/assets/app.js`);
  const list = (await c.json('/api/previews')).data.previews;
  assert.equal(list[0].kind, 'build');
  runner.script = { lines: ['ok\n'] };
});

test('main UI may embed previews but nothing may embed the UI', async () => {
  const res = await fetch(`${srv.base}/`);
  const csp = res.headers.get('content-security-policy') ?? '';
  assert.match(csp, /frame-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
});

test('preview hosts serve only preview files at their root, never the app or API', async () => {
  const http = await import('node:http');
  const c = new Client(srv.base);
  const insp = await inspect(c, 'static-site');
  const p = (await c.json('/api/previews', { json: { inspectionId: insp.id } })).data.preview;
  const port = Number(new URL(srv.base).port);
  const get = (host: string, path: string) =>
    new Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }>((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path, headers: { host: `${host}:${port}` } }, (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      });
      req.on('error', reject);
      req.end();
    });
  const root = await get(`${p.token}.preview.localhost`, '/');
  assert.equal(root.status, 200);
  assert.match(root.body, /Tiny Tip Calculator/);
  assert.match(String(root.headers['content-security-policy']), /^sandbox .*frame-ancestors http:\/\/localhost:\* http:\/\/127\.0\.0\.1:\*/);
  assert.equal(root.headers['x-frame-options'], undefined, 'the app may embed it');
  assert.equal(root.headers['set-cookie'], undefined);
  assert.equal((await get(`${p.token}.preview.localhost`, '/img/logo.svg')).status, 200, 'absolute paths resolve at the preview root');
  const api = await get(`${p.token}.preview.localhost`, '/api/config');
  assert.equal(api.status, 404, 'the API is not reachable on a preview host');
  assert.doesNotMatch(api.body, /productName/);
  assert.equal((await get(`${p.token}.preview.localhost`, '/healthz')).status, 404);
  assert.equal((await get(`evil.preview.localhost`, '/')).status, 404);
  assert.equal((await get(`${'f'.repeat(32)}.preview.localhost`, '/')).status, 404);
  const ui = await fetch(`${srv.base}/`);
  assert.match(ui.headers.get('content-security-policy') ?? '', /frame-src 'self' http:\/\/\*\.preview\.localhost:\*/);
});
