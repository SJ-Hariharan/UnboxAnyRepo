/**
 * Registry egress proxy for the dependency-install step.
 *
 * Runs outside the sandbox, attached to the internal "fetch" Docker network
 * (the only thing install containers can reach) and to an outbound network.
 *
 * - HTTP CONNECT only (HTTPS tunnels); plain HTTP requests are refused;
 * - exact hostname allowlist, port 443 only;
 * - destination resolved here and validated as public at connect time
 *   (blocks private, loopback, link-local/metadata, CGNAT… and DNS rebinding);
 * - limits on concurrent tunnels, idle time, tunnel lifetime and bytes.
 *
 * It does not inspect TLS traffic. Package managers verify their own
 * integrity data; the proxy's job is to keep the sandbox off everything else.
 */
import http from 'node:http';
import net from 'node:net';
import type { Duplex } from 'node:stream';
import { resolvePublic } from '../github/netguard.ts';
import type { LookupAddress } from 'node:dns';

export const DEFAULT_ALLOWLIST = [
  'registry.npmjs.org',
  'pypi.org',
  'files.pythonhosted.org',
  'proxy.golang.org',
  'sum.golang.org',
  'index.crates.io',
  'static.crates.io',
];

export interface EgressProxyOptions {
  allowlist: readonly string[];
  maxConnections?: number;
  idleTimeoutMs?: number;
  maxTunnelMs?: number;
  maxBytesPerTunnel?: number;
  log?: (line: string) => void;
  /** Injectable for tests. */
  resolve?: (host: string) => Promise<LookupAddress[]>;
  connect?: (address: string, port: number) => net.Socket;
}

const HOST_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

export function parseConnectTarget(target: string | undefined): { host: string; port: number } | null {
  if (!target) return null;
  const m = /^([^:/\s]+):(\d{1,5})$/.exec(target);
  if (!m) return null;
  const host = (m[1] as string).toLowerCase().replace(/\.$/, '');
  const port = Number(m[2]);
  if (!HOST_RE.test(host) || port < 1 || port > 65535) return null;
  return { host, port };
}

export function createEgressProxy(opts: EgressProxyOptions): http.Server {
  const allow = new Set(opts.allowlist.map((h) => h.toLowerCase()));
  const maxConnections = opts.maxConnections ?? 64;
  const idleTimeoutMs = opts.idleTimeoutMs ?? 60_000;
  const maxTunnelMs = opts.maxTunnelMs ?? 15 * 60_000;
  const maxBytes = opts.maxBytesPerTunnel ?? 2 * 1024 * 1024 * 1024;
  const log = opts.log ?? ((l: string) => console.log(l));
  const resolve = opts.resolve ?? ((h: string) => resolvePublic(h));
  const connect = opts.connect ?? ((address: string, port: number) => net.connect({ host: address, port }));
  let active = 0;

  const server = http.createServer((req, res) => {
    log(`deny method=${req.method ?? '?'} reason=not-connect`);
    res.writeHead(405, { 'Content-Type': 'text/plain' }).end('Only HTTPS CONNECT tunnels to package registries are allowed.\n');
  });

  const refuse = (socket: Duplex, code: number, reason: string, target: string) => {
    log(`deny target=${target.slice(0, 120)} reason=${reason}`);
    socket.end(`HTTP/1.1 ${code} ${code === 403 ? 'Forbidden' : 'Service Unavailable'}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
  };

  server.on('connect', (req: http.IncomingMessage, client: Duplex, head: Buffer) => {
    const raw = req.url ?? '';
    const target = parseConnectTarget(raw);
    if (!target) return refuse(client, 403, 'bad-target', raw);
    if (target.port !== 443) return refuse(client, 403, 'port-not-allowed', raw);
    if (!allow.has(target.host)) return refuse(client, 403, 'host-not-allowlisted', raw);
    if (active >= maxConnections) return refuse(client, 503, 'too-many-tunnels', raw);
    active++;
    let released = false;
    const release = () => {
      if (!released) {
        released = true;
        active--;
      }
    };
    client.on('error', () => {});

    resolve(target.host).then(
      (addrs) => {
        const addr = addrs[0] as LookupAddress;
        const upstream = connect(addr.address, 443);
        let bytes = head.length;
        const lifetime = setTimeout(() => {
          log(`close target=${target.host} reason=max-lifetime`);
          upstream.destroy();
          client.destroy();
        }, maxTunnelMs);
        const done = () => {
          clearTimeout(lifetime);
          release();
        };
        upstream.setTimeout(idleTimeoutMs, () => {
          upstream.destroy();
          client.destroy();
        });
        upstream.on('error', () => client.destroy());
        upstream.on('close', () => {
          client.destroy();
          done();
        });
        client.on('close', () => {
          upstream.destroy();
          done();
        });
        const count = (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes > maxBytes) {
            log(`close target=${target.host} reason=byte-limit`);
            upstream.destroy();
            client.destroy();
          }
        };
        upstream.once('connect', () => {
          log(`allow target=${target.host}:443 ip=${addr.address}`);
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          if (head.length > 0) upstream.write(head);
          upstream.on('data', count);
          client.on('data', count);
          upstream.pipe(client);
          client.pipe(upstream);
        });
      },
      () => {
        release();
        refuse(client, 403, 'non-public-or-unresolvable', raw);
      },
    );
  });

  server.on('clientError', (_err, socket) => socket.destroy());
  return server;
}
