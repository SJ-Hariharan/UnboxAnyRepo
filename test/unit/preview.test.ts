import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PreviewStore, filesFromTar, checkHealth, contentType, previewHeaders, PreviewError } from '../../src/preview/store.ts';
import { sanitizeArchive } from '../../src/source/archive.ts';
import { repoArchive, buildTar } from '../helpers/tarbuilder.ts';

const LIM = { maxCompressedBytes: 1e7, maxUncompressedBytes: 1e7, maxFiles: 100, maxFileBytes: 1e6 };

test('static preview files come only from the requested root of the sanitized snapshot', async () => {
  const snap = await sanitizeArchive(repoArchive({ 'docs/index.html': '<html><img src="a.png"><script src="/js/x.js"></script></html>', 'docs/a.png': 'png', 'src/secret.env': 'X=1', 'README.md': 'r' }), LIM);
  const files = await filesFromTar(snap.sanitizedTarGz, { gzip: true, prefix: 'src/docs', maxBytes: 1e6 });
  assert.deepEqual([...files.keys()].sort(), ['a.png', 'index.html']);
  assert.equal(files.get('index.html')?.type, 'text/html; charset=utf-8');
  const health = checkHealth(files);
  assert.equal(health.checks.find((c) => c.name === 'Entry page')?.ok, true);
  const refs = health.checks.find((c) => c.name.startsWith('Local files'));
  assert.equal(refs?.ok, false);
  assert.match(refs?.detail ?? '', /js\/x\.js/);
  await assert.rejects(filesFromTar(snap.sanitizedTarGz, { gzip: true, prefix: 'src/docs', maxBytes: 5 }), (e: unknown) => e instanceof PreviewError && e.code === 'too_large');
});

test('build artifacts with unsafe paths are rejected', async () => {
  const tar = buildTar([{ name: './index.html', data: '<html>' }, { name: './../escape.txt', data: 'x' }]);
  await assert.rejects(filesFromTar(tar, { gzip: false, prefix: '', maxBytes: 1e6 }), (e: unknown) => e instanceof PreviewError && e.code === 'unsafe_output');
  const ok = await filesFromTar(buildTar([{ name: './index.html', data: '<html>' }, { name: './assets/app.js', data: 'x' }]), { gzip: false, prefix: '', maxBytes: 1e6 });
  assert.deepEqual([...ok.keys()].sort(), ['assets/app.js', 'index.html']);
});

test('preview store: random tokens, ownership, expiry, stop/restart and per-session cap', async () => {
  const store = new PreviewStore({ ttlSec: 60, maxBytes: 1e6, perSession: 2 });
  let builds = 0;
  const rebuild = async () => {
    builds++;
    return new Map([['index.html', { data: Buffer.from('<html>hi</html>'), type: 'text/html' }]]);
  };
  const base = { sessionId: 'A', inspectionId: 'i', repo: 'o/r', commitSha: 'c'.repeat(40), kind: 'static' as const, root: '', rebuild };
  const p1 = await store.create(base);
  assert.match(p1.token, /^[a-f0-9]{32}$/);
  assert.ok(store.serve(p1.token));
  assert.equal(store.owned(p1.token, 'B'), undefined, 'other sessions cannot manage it');
  assert.equal(store.stop(p1.token, 'B'), undefined);
  assert.equal(store.list('B').length, 0);
  assert.equal(store.stop(p1.token, 'A')?.state, 'stopped');
  assert.equal(store.serve(p1.token), undefined, 'stopped previews are not served');
  const restarted = await store.restart(p1.token, 'A');
  assert.equal(restarted?.state, 'running');
  assert.equal(builds, 2);
  const p2 = await store.create(base);
  const p3 = await store.create(base);
  assert.equal(store.serve(p1.token), undefined, 'oldest replaced at the per-session cap');
  assert.ok(store.serve(p2.token) && store.serve(p3.token));
  assert.equal(store.serve('../../etc/passwd'), undefined);
  // Expiry
  const short = new PreviewStore({ ttlSec: 60, maxBytes: 1e6, perSession: 2 });
  const p = await short.create(base);
  (short as unknown as { items: Map<string, { expiresAt: number }> }).items.get(p.token)!.expiresAt = Date.now() - 1;
  assert.equal(short.serve(p.token), undefined);
  assert.equal(short.list('A')[0]?.state, 'expired');
});

test('preview responses run in an opaque origin and allow only their own embedding', () => {
  const h = previewHeaders('text/html');
  assert.match(h['Content-Security-Policy'] ?? '', /^sandbox /);
  assert.doesNotMatch(h['Content-Security-Policy'] ?? '', /allow-same-origin/);
  assert.match(h['Content-Security-Policy'] ?? '', /frame-ancestors 'self'/);
  assert.equal(h['X-Content-Type-Options'], 'nosniff');
  assert.equal(contentType('a.unknownext'), 'application/octet-stream', 'unknown files are never served as HTML');
  assert.equal(contentType('x.svg'), 'image/svg+xml');
});
