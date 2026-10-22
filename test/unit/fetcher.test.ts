import { test } from 'node:test';
import assert from 'node:assert/strict';
import { safeFetch, FetchError } from '../../src/github/fetcher.ts';
import type { Transport, TransportResponse } from '../../src/github/fetcher.ts';

type Scripted = { status: number; headers?: Record<string, string>; body?: Buffer | Buffer[]; delayMs?: number };

function scripted(responses: Record<string, Scripted>, seen: { url: string; headers: Record<string, string> }[] = []): Transport {
  return async (url, headers, signal) => {
    seen.push({ url: url.toString(), headers });
    const r = responses[url.toString()];
    if (!r) throw Object.assign(new Error('no route'), { code: 'ECONNREFUSED' });
    if (r.delayMs) {
      await new Promise<void>((resolve, reject) => {
        const t = setTimeout(resolve, r.delayMs);
        signal.addEventListener('abort', () => {
          clearTimeout(t);
          reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
        });
      });
    }
    const chunks = r.body === undefined ? [] : Array.isArray(r.body) ? r.body : [r.body];
    let destroyed = false;
    const res: TransportResponse = {
      status: r.status,
      headers: r.headers ?? {},
      body: (async function* () {
        for (const c of chunks) {
          if (destroyed) return;
          yield c;
        }
      })(),
      destroy: () => {
        destroyed = true;
      },
    };
    return res;
  };
}

const HOSTS = new Set(['api.github.com', 'codeload.github.com']);

test('follows an allowlisted redirect and drops credentials across hosts', async () => {
  const seen: { url: string; headers: Record<string, string> }[] = [];
  const transport = scripted(
    {
      'https://api.github.com/repos/a/b/tarball/x': { status: 302, headers: { location: 'https://codeload.github.com/a/b/tar.gz/x' } },
      'https://codeload.github.com/a/b/tar.gz/x': { status: 200, body: Buffer.from('ok') },
    },
    seen,
  );
  const res = await safeFetch('https://api.github.com/repos/a/b/tarball/x', {
    allowedHosts: HOSTS,
    sensitiveHeaders: { authorization: 'Bearer secret' },
    maxBytes: 100,
    timeoutMs: 1000,
    transport,
  });
  assert.equal(res.body.toString(), 'ok');
  assert.equal(seen[0]?.headers.authorization, 'Bearer secret');
  assert.equal(seen[1]?.headers.authorization, undefined);
});

test('rejects redirects to non-allowlisted hosts, http, other ports, credentials and private targets', async () => {
  const targets = [
    'https://evil.example/x',
    'http://codeload.github.com/x',
    'https://codeload.github.com:8443/x',
    'https://user:pw@codeload.github.com/x',
    'http://169.254.169.254/latest/meta-data/',
    'https://127.0.0.1/x',
    'https://[::1]/x',
    'https://localhost/x',
    'file:///etc/passwd',
    'gopher://codeload.github.com/x',
  ];
  for (const location of targets) {
    const transport = scripted({ 'https://api.github.com/a': { status: 301, headers: { location } } });
    await assert.rejects(
      safeFetch('https://api.github.com/a', { allowedHosts: HOSTS, maxBytes: 10, timeoutMs: 1000, transport }),
      (e: unknown) => e instanceof FetchError && e.code === 'redirect_not_allowed',
      location,
    );
  }
});

test('rejects a non-allowlisted starting URL without making a request', async () => {
  const seen: { url: string; headers: Record<string, string> }[] = [];
  await assert.rejects(
    safeFetch('https://example.com/', { allowedHosts: HOSTS, maxBytes: 10, timeoutMs: 1000, transport: scripted({}, seen) }),
    FetchError,
  );
  assert.equal(seen.length, 0);
});

test('limits redirect hops', async () => {
  const transport = scripted({
    'https://api.github.com/1': { status: 302, headers: { location: '/2' } },
    'https://api.github.com/2': { status: 302, headers: { location: '/3' } },
    'https://api.github.com/3': { status: 302, headers: { location: '/1' } },
  });
  await assert.rejects(
    safeFetch('https://api.github.com/1', { allowedHosts: HOSTS, maxBytes: 10, timeoutMs: 1000, maxRedirects: 2, transport }),
    (e: unknown) => e instanceof FetchError && e.code === 'too_many_redirects',
  );
});

test('enforces size limits by declared length and by streamed bytes', async () => {
  const declared = scripted({ 'https://api.github.com/x': { status: 200, headers: { 'content-length': '1000' }, body: Buffer.alloc(10) } });
  await assert.rejects(
    safeFetch('https://api.github.com/x', { allowedHosts: HOSTS, maxBytes: 100, timeoutMs: 1000, transport: declared }),
    (e: unknown) => e instanceof FetchError && e.code === 'too_large',
  );
  const streamed = scripted({ 'https://api.github.com/x': { status: 200, body: [Buffer.alloc(60), Buffer.alloc(60)] } });
  await assert.rejects(
    safeFetch('https://api.github.com/x', { allowedHosts: HOSTS, maxBytes: 100, timeoutMs: 1000, transport: streamed }),
    (e: unknown) => e instanceof FetchError && e.code === 'too_large',
  );
});

test('times out slow responses', async () => {
  const slow = scripted({ 'https://api.github.com/x': { status: 200, delayMs: 2000 } });
  await assert.rejects(
    safeFetch('https://api.github.com/x', { allowedHosts: HOSTS, maxBytes: 100, timeoutMs: 50, transport: slow }),
    (e: unknown) => e instanceof FetchError && e.code === 'timeout',
  );
});
