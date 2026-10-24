/**
 * Minimal HTTPS GET client for a fixed allowlist of hosts.
 *
 * - https only, default port only, allowlisted hostnames only;
 * - redirects followed manually (bounded), each hop re-validated;
 *   credentials are dropped when a redirect changes host;
 * - direct connections go through `guardedLookup` (public IPs only);
 * - an explicitly configured HTTP CONNECT proxy may be used instead; then the
 *   proxy is responsible for destination IP policy (documented);
 * - hard limits on response size and total time.
 */
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import type { IncomingHttpHeaders } from 'node:http';
import { guardedLookup } from './netguard.ts';

export type FetchErrorCode =
  | 'blocked_destination'
  | 'redirect_not_allowed'
  | 'too_many_redirects'
  | 'too_large'
  | 'timeout'
  | 'aborted'
  | 'network';

export class FetchError extends Error {
  readonly code: FetchErrorCode;
  constructor(code: FetchErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export interface TransportResponse {
  status: number;
  headers: IncomingHttpHeaders;
  body: AsyncIterable<Buffer>;
  destroy(): void;
}

/** A transport performs exactly one request (no redirects). Injectable for tests. */
export type Transport = (url: URL, headers: Record<string, string>, signal: AbortSignal, body?: Buffer) => Promise<TransportResponse>;

export interface SafeFetchOptions {
  allowedHosts: ReadonlySet<string>;
  headers?: Record<string, string>;
  /** Headers only sent to the first host (e.g. Authorization); dropped on cross-host redirects. */
  sensitiveHeaders?: Record<string, string>;
  maxBytes: number;
  timeoutMs: number;
  maxRedirects?: number;
  signal?: AbortSignal;
  transport?: Transport;
  /** JSON or other request body; makes the request a POST. POSTs never follow redirects. */
  body?: Buffer;
}

export interface SafeResponse {
  status: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
  finalUrl: string;
}

export function validateTarget(url: URL, allowedHosts: ReadonlySet<string>): void {
  if (url.protocol !== 'https:') throw new FetchError('redirect_not_allowed', 'Only HTTPS destinations are allowed');
  if (url.username || url.password) throw new FetchError('redirect_not_allowed', 'Credentials in URL are not allowed');
  if (url.port !== '' && url.port !== '443') throw new FetchError('redirect_not_allowed', 'Non-default port not allowed');
  if (!allowedHosts.has(url.hostname.toLowerCase())) {
    throw new FetchError('redirect_not_allowed', 'Destination host is not on the allowlist');
  }
}

export async function safeFetch(input: string, opts: SafeFetchOptions): Promise<SafeResponse> {
  const transport = opts.transport ?? defaultTransport;
  const maxRedirects = opts.body ? 0 : (opts.maxRedirects ?? 3);
  const controller = new AbortController();
  const onOuterAbort = () => controller.abort();
  opts.signal?.addEventListener('abort', onOuterAbort, { once: true });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, opts.timeoutMs);

  try {
    let url = new URL(input);
    const firstHost = url.hostname.toLowerCase();
    for (let hop = 0; ; hop++) {
      validateTarget(url, opts.allowedHosts);
      const headers: Record<string, string> = { 'accept-encoding': 'identity', ...opts.headers };
      if (url.hostname.toLowerCase() === firstHost && opts.sensitiveHeaders) Object.assign(headers, opts.sensitiveHeaders);

      let res: TransportResponse;
      try {
        res = await transport(url, headers, controller.signal, opts.body);
      } catch (err) {
        throw mapError(err, timedOut, controller.signal.aborted);
      }

      if (res.status >= 300 && res.status < 400 && res.headers.location !== undefined) {
        res.destroy();
        if (opts.body) throw new FetchError('redirect_not_allowed', 'Redirects are not followed for POST requests');
        if (hop >= maxRedirects) throw new FetchError('too_many_redirects', 'Too many redirects');
        const loc = Array.isArray(res.headers.location) ? res.headers.location[0] : res.headers.location;
        let next: URL;
        try {
          next = new URL(String(loc), url);
        } catch {
          throw new FetchError('redirect_not_allowed', 'Invalid redirect');
        }
        url = next;
        continue;
      }

      const declared = Number(res.headers['content-length']);
      if (Number.isFinite(declared) && declared > opts.maxBytes) {
        res.destroy();
        throw new FetchError('too_large', 'Response is larger than the allowed limit');
      }
      const chunks: Buffer[] = [];
      let total = 0;
      try {
        for await (const chunk of res.body) {
          total += chunk.length;
          if (total > opts.maxBytes) {
            res.destroy();
            throw new FetchError('too_large', 'Response is larger than the allowed limit');
          }
          chunks.push(chunk);
        }
      } catch (err) {
        if (err instanceof FetchError) throw err;
        throw mapError(err, timedOut, controller.signal.aborted);
      }
      return { status: res.status, headers: res.headers, body: Buffer.concat(chunks, total), finalUrl: url.toString() };
    }
  } finally {
    clearTimeout(timer);
    opts.signal?.removeEventListener('abort', onOuterAbort);
  }
}

function mapError(err: unknown, timedOut: boolean, aborted: boolean): FetchError {
  if (err instanceof FetchError) return err;
  if (timedOut) return new FetchError('timeout', 'The request timed out');
  if (aborted) return new FetchError('aborted', 'The request was cancelled');
  const code = (err as { code?: string } | null)?.code;
  if (code === 'EBLOCKED') return new FetchError('blocked_destination', 'Destination resolved to a non-public address');
  return new FetchError('network', 'Network error while contacting GitHub');
}

function wrapIncoming(res: http.IncomingMessage, req: http.ClientRequest): TransportResponse {
  return {
    status: res.statusCode ?? 0,
    headers: res.headers,
    body: res,
    destroy: () => {
      res.destroy();
      req.destroy();
    },
  };
}

/** Direct HTTPS with guarded DNS lookup (public addresses only). */
export const directTransport: Transport = (url, headers, signal, body) =>
  new Promise((resolve, reject) => {
    const req = https.request(
      {
        protocol: 'https:',
        hostname: url.hostname,
        port: 443,
        path: url.pathname + url.search,
        method: body ? 'POST' : 'GET',
        headers: body ? { ...headers, 'content-length': String(body.length) } : headers,
        lookup: guardedLookup as unknown as typeof import('node:dns').lookup,
        agent: false,
        signal,
      },
      (res) => resolve(wrapIncoming(res, req)),
    );
    req.on('error', reject);
    req.end(body);
  });

/**
 * HTTPS through an explicit HTTP CONNECT proxy. Destination-IP policy is the
 * proxy's responsibility in this mode; we still enforce host allowlisting.
 */
export function proxyTransport(proxyUrl: string): Transport {
  const proxy = new URL(proxyUrl);
  return (url, headers, signal, body) =>
    new Promise((resolve, reject) => {
      const target = `${url.hostname}:443`;
      const connectReq = http.request({
        hostname: proxy.hostname,
        port: Number(proxy.port || 80),
        method: 'CONNECT',
        path: target,
        headers: { host: target },
        signal,
      });
      connectReq.on('error', reject);
      connectReq.on('connect', (res, socket) => {
        if (res.statusCode !== 200) {
          socket.destroy();
          reject(new FetchError('network', 'Outbound proxy refused the connection'));
          return;
        }
        const req = https.request(
          {
            hostname: url.hostname,
            port: 443,
            path: url.pathname + url.search,
            method: body ? 'POST' : 'GET',
            headers: body ? { ...headers, 'content-length': String(body.length) } : headers,
            agent: false,
            signal,
            createConnection: () => tls.connect({ socket, servername: url.hostname, ALPNProtocols: ['http/1.1'] }),
          },
          (r) => resolve(wrapIncoming(r, req)),
        );
        req.on('error', reject);
        req.end(body);
      });
      connectReq.end();
    });
}

let defaultTransport: Transport = directTransport;

/** Configure the process-wide transport once at startup. */
export function configureOutboundProxy(proxyUrl: string | undefined): void {
  defaultTransport = proxyUrl ? proxyTransport(proxyUrl) : directTransport;
}
