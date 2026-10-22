import { randomBytes } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

export class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryAfterSec: number | undefined;
  constructor(status: number, code: string, message: string, retryAfterSec?: number) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryAfterSec = retryAfterSec;
  }
}

export const SESSION_COOKIE = 'rr_sid';
const SESSION_RE = /^[A-Za-z0-9_-]{43}$/;

export function securityHeaders(res: ServerResponse): void {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
}

export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(data),
    ...headers,
  });
  res.end(data);
}

export function sendError(res: ServerResponse, err: HttpError): void {
  const headers: Record<string, string> = {};
  if (err.retryAfterSec !== undefined) headers['Retry-After'] = String(err.retryAfterSec);
  sendJson(
    res,
    err.status,
    { error: { code: err.code, message: err.message, ...(err.retryAfterSec !== undefined ? { retryAfterSec: err.retryAfterSec } : {}) } },
    headers,
  );
}

export async function readJsonBody(req: IncomingMessage, maxBytes = 8 * 1024): Promise<Record<string, unknown>> {
  const type = (req.headers['content-type'] ?? '').split(';')[0]?.trim().toLowerCase();
  if (type !== 'application/json') throw new HttpError(415, 'unsupported_media_type', 'Send JSON (Content-Type: application/json).');
  const declared = Number(req.headers['content-length']);
  if (Number.isFinite(declared) && declared > maxBytes) throw new HttpError(413, 'body_too_large', 'Request body is too large.');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > maxBytes) throw new HttpError(413, 'body_too_large', 'Request body is too large.');
    chunks.push(chunk as Buffer);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'invalid_json', 'Request body is not valid JSON.');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new HttpError(400, 'invalid_body', 'Request body must be a JSON object.');
  }
  return parsed as Record<string, unknown>;
}

/** Reject unknown fields so callers cannot smuggle e.g. a "command". */
export function onlyKeys(body: Record<string, unknown>, allowed: readonly string[]): void {
  for (const k of Object.keys(body)) {
    if (!allowed.includes(k)) throw new HttpError(400, 'unexpected_field', `Unexpected field "${k.slice(0, 40).replace(/[^\w-]/g, '?')}".`);
  }
}

export function parseCookies(header: string | undefined): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of (header ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    out.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
  }
  return out;
}

/** Returns the session id, issuing a new random one (and cookie) if needed. */
export function ensureSession(req: IncomingMessage, res: ServerResponse, secure: boolean): string {
  const existing = parseCookies(req.headers.cookie).get(SESSION_COOKIE);
  if (existing && SESSION_RE.test(existing)) return existing;
  const id = randomBytes(32).toString('base64url');
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=${id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400${secure ? '; Secure' : ''}`,
  );
  return id;
}

export function clientIp(req: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    const raw = Array.isArray(xff) ? xff.join(',') : (xff ?? '');
    // Behind exactly one trusted proxy, the right-most entry was added by it.
    const last = raw.split(',').map((s) => s.trim()).filter(Boolean).at(-1);
    if (last) return last.slice(0, 64);
  }
  return (req.socket.remoteAddress ?? 'unknown').slice(0, 64);
}

/** CSRF defense for state-changing requests (in addition to SameSite=Strict cookies). */
export function checkOrigin(req: IncomingMessage, publicOrigin: string | undefined): void {
  const site = req.headers['sec-fetch-site'];
  if (site === 'cross-site') throw new HttpError(403, 'cross_site', 'Cross-site requests are not allowed.');
  const origin = req.headers.origin;
  if (origin === undefined) return;
  const host = req.headers.host;
  const allowed = publicOrigin ? [publicOrigin] : host ? [`http://${host}`, `https://${host}`] : [];
  if (!allowed.includes(origin)) throw new HttpError(403, 'bad_origin', 'Request origin is not allowed.');
}
