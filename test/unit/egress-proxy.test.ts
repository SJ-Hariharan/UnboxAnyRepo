import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createEgressProxy, parseConnectTarget } from '../../src/egress-proxy/proxy.ts';
import { resolvePublic } from '../../src/github/netguard.ts';

/** Local echo server standing in for a registry. */
async function echoServer() {
  const s = net.createServer((sock) => sock.pipe(sock));
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  return { server: s, port: (s.address() as AddressInfo).port };
}

async function proxy(opts: Partial<Parameters<typeof createEgressProxy>[0]> & { echoPort: number; ip?: string }) {
  const logs: string[] = [];
  const p = createEgressProxy({
    allowlist: ['registry.npmjs.org', 'pypi.org'],
    log: (l) => logs.push(l),
    // Resolution is validated with the real guard; "public" addresses are routed to the local echo server.
    resolve: (h) => resolvePublic(h, async () => [{ address: opts.ip ?? '104.16.0.1', family: 4 }]),
    connect: () => net.connect({ host: '127.0.0.1', port: opts.echoPort }),
    ...opts,
  });
  await new Promise<void>((r) => p.listen(0, '127.0.0.1', r));
  return { p, port: (p.address() as AddressInfo).port, logs };
}

function connectVia(port: number, target: string, payload?: string): Promise<{ status: number; echoed: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method: 'CONNECT', path: target });
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200 || payload === undefined) {
        socket.destroy();
        return resolve({ status: res.statusCode ?? 0, echoed: '' });
      }
      socket.write(payload);
      socket.once('data', (d) => {
        socket.destroy();
        resolve({ status: 200, echoed: d.toString() });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

test('tunnels only to allowlisted hosts on port 443', async () => {
  const echo = await echoServer();
  const { p, port, logs } = await proxy({ echoPort: echo.port });
  try {
    assert.deepEqual(await connectVia(port, 'registry.npmjs.org:443', 'hello'), { status: 200, echoed: 'hello' });
    assert.equal((await connectVia(port, 'evil.example:443')).status, 403);
    assert.equal((await connectVia(port, 'registry.npmjs.org.evil.example:443')).status, 403);
    assert.equal((await connectVia(port, 'registry.npmjs.org:80')).status, 403);
    assert.equal((await connectVia(port, 'registry.npmjs.org:22')).status, 403);
    assert.equal((await connectVia(port, '169.254.169.254:443')).status, 403);
    assert.equal((await connectVia(port, '127.0.0.1:443')).status, 403);
    assert.ok(logs.some((l) => l.includes('allow target=registry.npmjs.org:443')));
    assert.ok(logs.some((l) => l.includes('reason=host-not-allowlisted')));
  } finally {
    p.close();
    echo.server.close();
  }
});

test('refuses allowlisted names that resolve to private or metadata addresses (DNS rebinding)', async () => {
  const echo = await echoServer();
  for (const ip of ['10.0.0.5', '169.254.169.254', '127.0.0.1', '100.64.1.1', '::ffff:127.0.0.1']) {
    const { p, port } = await proxy({ echoPort: echo.port, ip });
    try {
      assert.equal((await connectVia(port, 'pypi.org:443')).status, 403, ip);
    } finally {
      p.close();
    }
  }
  echo.server.close();
});

test('refuses plain HTTP proxy requests', async () => {
  const echo = await echoServer();
  const { p, port } = await proxy({ echoPort: echo.port });
  try {
    const status = await new Promise<number>((resolve) => {
      http.get({ host: '127.0.0.1', port, path: 'http://registry.npmjs.org/x' }, (res) => resolve(res.statusCode ?? 0));
    });
    assert.equal(status, 405);
  } finally {
    p.close();
    echo.server.close();
  }
});

test('enforces the concurrent tunnel cap and the per-tunnel byte limit', async () => {
  const echo = await echoServer();
  const { p, port } = await proxy({ echoPort: echo.port, maxConnections: 1, maxBytesPerTunnel: 1000 });
  try {
    // Hold one tunnel open.
    const held = await new Promise<net.Socket>((resolve) => {
      const req = http.request({ host: '127.0.0.1', port, method: 'CONNECT', path: 'pypi.org:443' });
      req.on('connect', (_res, socket) => resolve(socket));
      req.end();
    });
    assert.equal((await connectVia(port, 'pypi.org:443')).status, 503);
    // Exceed the byte limit on the held tunnel: the proxy closes it.
    const closed = new Promise<void>((r) => held.on('close', () => r()));
    held.on('error', () => {});
    held.write(Buffer.alloc(5000));
    await closed;
  } finally {
    p.close();
    echo.server.close();
  }
});

test('CONNECT target parsing', () => {
  assert.deepEqual(parseConnectTarget('Registry.NPMJS.org:443'), { host: 'registry.npmjs.org', port: 443 });
  for (const bad of [undefined, '', 'host', 'host:', 'host:99999', 'a b:443', '[::1]:443', 'http://x:443', 'x/y:443', '-x.com:443']) {
    assert.equal(parseConnectTarget(bad), null, String(bad));
  }
});
