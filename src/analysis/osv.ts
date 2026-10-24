/**
 * Known-vulnerability lookup through the OSV.dev API (https://osv.dev).
 *
 * Only exact package versions are queried. The request goes through the same
 * guarded HTTPS client as GitHub traffic: a fixed host, HTTPS on 443, public
 * IP addresses only, no redirects for POST, bounded size and time.
 *
 * Vulnerability data comes from OSV.dev and its upstream databases (GitHub
 * Advisory Database, PyPA, Go, RustSec, ...). It reflects what was published
 * at query time and can be incomplete.
 */
import { createHash } from 'node:crypto';
import { safeFetch } from '../github/fetcher.ts';
import type { Transport } from '../github/fetcher.ts';
import type { DependencyPackage, Finding, Severity, ToolRun } from './types.ts';
import { isPlainObject, displayText } from '../detect/util.ts';

const OSV_HOSTS = new Set(['api.osv.dev']);
const BATCH = 1000;
const MAX_DETAILS = 100;
const DETAIL_CONCURRENCY = 6;
const VULN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,80}$/;

export interface OsvOptions {
  userAgent: string;
  timeoutMs: number;
  signal?: AbortSignal;
  transport?: Transport;
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: { package?: { ecosystem?: string; name?: string }; ranges?: { type?: string; events?: Record<string, string>[] }[]; database_specific?: { severity?: string } }[];
  references?: { type?: string; url?: string }[];
}

async function post(path: string, body: unknown, opts: OsvOptions, maxBytes: number): Promise<unknown> {
  const res = await safeFetch(`https://api.osv.dev${path}`, {
    allowedHosts: OSV_HOSTS,
    headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': opts.userAgent },
    body: Buffer.from(JSON.stringify(body)),
    maxBytes,
    timeoutMs: opts.timeoutMs,
    ...(opts.signal ? { signal: opts.signal } : {}),
    ...(opts.transport ? { transport: opts.transport } : {}),
  });
  if (res.status !== 200) throw new Error(`OSV returned HTTP ${res.status}`);
  return JSON.parse(res.body.toString('utf8'));
}

async function get(path: string, opts: OsvOptions): Promise<unknown> {
  const res = await safeFetch(`https://api.osv.dev${path}`, {
    allowedHosts: OSV_HOSTS,
    headers: { accept: 'application/json', 'user-agent': opts.userAgent },
    maxBytes: 2 * 1024 * 1024,
    timeoutMs: opts.timeoutMs,
    maxRedirects: 0,
    ...(opts.signal ? { signal: opts.signal } : {}),
    ...(opts.transport ? { transport: opts.transport } : {}),
  });
  if (res.status !== 200) throw new Error(`OSV returned HTTP ${res.status}`);
  return JSON.parse(res.body.toString('utf8'));
}

// --------------------------------------------------------------- severity

const CVSS3_WEIGHTS: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
};

function roundUp(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/** CVSS v3.x base score from a vector string, or undefined if it cannot be parsed. */
export function cvss3BaseScore(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;
  const m: Record<string, string> = {};
  for (const part of vector.split('/').slice(1)) {
    const [k, v] = part.split(':');
    if (k && v) m[k] = v;
  }
  const S = m.S;
  const PR = m.PR;
  const get = (k: string) => CVSS3_WEIGHTS[k]?.[m[k] ?? ''];
  const [av, ac, ui, c, i, a] = [get('AV'), get('AC'), get('UI'), get('C'), get('I'), get('A')];
  if (av === undefined || ac === undefined || ui === undefined || c === undefined || i === undefined || a === undefined || (S !== 'U' && S !== 'C')) return undefined;
  const pr = PR === 'N' ? 0.85 : PR === 'L' ? (S === 'C' ? 0.68 : 0.62) : PR === 'H' ? (S === 'C' ? 0.5 : 0.27) : undefined;
  if (pr === undefined) return undefined;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  return S === 'U' ? roundUp(Math.min(impact + exploitability, 10)) : roundUp(Math.min(1.08 * (impact + exploitability), 10));
}

export function severityFromScore(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

export function osvSeverity(v: OsvVuln): Severity | undefined {
  const label = (v.database_specific?.severity ?? v.affected?.find((a) => a.database_specific?.severity)?.database_specific?.severity ?? '').toUpperCase();
  if (label === 'CRITICAL') return 'critical';
  if (label === 'HIGH') return 'high';
  if (label === 'MODERATE' || label === 'MEDIUM') return 'medium';
  if (label === 'LOW') return 'low';
  for (const s of v.severity ?? []) {
    if (typeof s.score === 'string' && s.type?.startsWith('CVSS_V3')) {
      const n = cvss3BaseScore(s.score);
      if (n !== undefined) return severityFromScore(n);
    }
  }
  return undefined;
}

function fixedVersions(v: OsvVuln, pkg: DependencyPackage): string[] {
  const out = new Set<string>();
  for (const a of v.affected ?? []) {
    if (a.package?.name?.toLowerCase() !== pkg.name.toLowerCase()) continue;
    // GIT ranges list commit hashes, not installable versions.
    for (const r of a.ranges ?? []) {
      if (r.type === 'GIT') continue;
      for (const e of r.events ?? []) if (typeof e.fixed === 'string' && e.fixed.length < 64) out.add(e.fixed);
    }
  }
  return [...out].slice(0, 5);
}

function stableId(...parts: string[]): string {
  return createHash('sha256').update(parts.join('\0')).digest('hex').slice(0, 12);
}

// ------------------------------------------------------------------ query

export async function checkOsv(packages: DependencyPackage[], opts: OsvOptions): Promise<{ findings: Finding[]; tool: ToolRun }> {
  const started = Date.now();
  const exact = packages.filter((p) => p.exact);
  if (exact.length === 0) {
    return { findings: [], tool: { tool: 'OSV.dev', state: 'skipped', message: 'No exactly pinned dependency versions to check.', findings: 0 } };
  }
  const hits: { pkg: DependencyPackage; ids: string[] }[] = [];
  try {
    for (let i = 0; i < exact.length && i < BATCH * 3; i += BATCH) {
      const batch = exact.slice(i, i + BATCH);
      const json = await post('/v1/querybatch', { queries: batch.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }, opts, 8 * 1024 * 1024);
      const results = isPlainObject(json) && Array.isArray(json.results) ? json.results : [];
      batch.forEach((pkg, j) => {
        const r = results[j];
        const vulns = isPlainObject(r) && Array.isArray(r.vulns) ? r.vulns : [];
        const ids = vulns.map((v) => (isPlainObject(v) && typeof v.id === 'string' && VULN_ID_RE.test(v.id) ? v.id : '')).filter(Boolean);
        if (ids.length) hits.push({ pkg, ids: ids.slice(0, 50) });
      });
    }
  } catch (err) {
    const timedOut = err instanceof Error && /timed out/i.test(err.message);
    return {
      findings: [],
      tool: { tool: 'OSV.dev', state: timedOut ? 'timed_out' : 'failed', message: 'The OSV.dev API could not be queried; dependency vulnerabilities were not checked.', findings: 0, durationMs: Date.now() - started },
    };
  }

  const uniqueIds = [...new Set(hits.flatMap((h) => h.ids))];
  const details = new Map<string, OsvVuln>();
  const queue = uniqueIds.slice(0, MAX_DETAILS);
  await Promise.all(
    Array.from({ length: DETAIL_CONCURRENCY }, async () => {
      for (let id = queue.shift(); id !== undefined; id = queue.shift()) {
        try {
          const v = await get(`/v1/vulns/${encodeURIComponent(id)}`, opts);
          if (isPlainObject(v) && v.id === id) details.set(id, v as unknown as OsvVuln);
        } catch {
          /* summarised below as missing details */
        }
      }
    }),
  );

  const findings: Finding[] = [];
  for (const { pkg, ids } of hits) {
    // The same vulnerability often appears under several ids (GHSA, PYSEC, CVE...): report it once,
    // preferring the entry with a summary and a severity.
    const rank = (id: string) => { const v = details.get(id); return (v?.summary ? 0 : 2) + (v && osvSeverity(v) ? 0 : 1); };
    const seen = new Set<string>();
    const ordered = [...ids].sort((a, b) => rank(a) - rank(b));
    for (const id of ordered) {
      if (seen.has(id)) continue;
      const v = details.get(id);
      seen.add(id);
      for (const alias of v?.aliases ?? []) seen.add(alias);
      for (const other of ids) if (details.get(other)?.aliases?.includes(id)) seen.add(other);
      const sev = v ? osvSeverity(v) : undefined;
      const fixed = v ? fixedVersions(v, pkg) : [];
      const aliases = (v?.aliases ?? []).filter((a) => typeof a === 'string' && VULN_ID_RE.test(a)).slice(0, 4);
      const refs = (v?.references ?? [])
        .map((r) => r.url)
        .filter((u): u is string => typeof u === 'string' && /^https:\/\/[^\s"<>]{1,300}$/.test(u))
        .slice(0, 3);
      findings.push({
        id: `UAR-OSV-${stableId(id, pkg.ecosystem, pkg.name, pkg.version)}`,
        ruleId: 'dependency.known-vulnerability',
        title: `${pkg.name}@${pkg.version}: ${v?.summary ? displayText(v.summary, 140) : id}`,
        category: 'vulnerable-dependency',
        severity: sev ?? 'medium',
        confidence: v ? 'high' : 'medium',
        status: v ? 'confirmed' : 'unverified',
        file: pkg.source.split(',')[0]?.trim(),
        evidence: `${pkg.ecosystem} ${pkg.name} ${pkg.version} matches ${id}${aliases.length ? ` (${aliases.join(', ')})` : ''}`,
        risk: v
          ? `${displayText(v.details ?? v.summary ?? 'A published advisory affects this version.', 400)}${sev ? '' : ' Severity was not rated by the source database.'}`
          : 'A published advisory affects this version. Details were not retrieved (lookup limit or error), so severity is unknown.',
        remediation: fixed.length ? `Upgrade ${pkg.name} to ${fixed.join(' or ')} or later, then regenerate the lockfile.` : `No fixed version is listed. Check ${id} for workarounds, or replace ${pkg.name}.`,
        method: 'osv',
        references: [`https://osv.dev/vulnerability/${id}`, ...refs],
        package: { ecosystem: pkg.ecosystem, name: pkg.name, version: pkg.version, ...(fixed.length ? { fixedIn: fixed } : {}) },
      });
    }
  }
  const missing = uniqueIds.length - details.size;
  return {
    findings,
    tool: {
      tool: 'OSV.dev',
      state: 'ran',
      message: `Checked ${Math.min(exact.length, BATCH * 3)} exact package version${exact.length === 1 ? '' : 's'}.${missing > 0 ? ` Details for ${missing} advisor${missing === 1 ? 'y were' : 'ies were'} not retrieved.` : ''}${exact.length > BATCH * 3 ? ` ${exact.length - BATCH * 3} packages beyond the limit were not checked.` : ''}`,
      findings: findings.length,
      durationMs: Date.now() - started,
    },
  };
}
