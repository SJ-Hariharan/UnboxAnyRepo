import { createHash } from 'node:crypto';
import type { Finding, Severity } from '../types.ts';
import { collapseControlChars } from '../../text.ts';

const SEV_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function sevIndex(s: Severity): number {
  return SEV_ORDER.indexOf(s);
}

/** One level lower (used for matches in test/example code). */
export function downgrade(s: Severity): Severity {
  return SEV_ORDER[Math.max(0, SEV_ORDER.indexOf(s) - 1)] as Severity;
}

/** Normalize an excerpt for display: single line, bounded, no control characters. */
export function excerpt(text: string, max = 180): string {
  const t = collapseControlChars(text).replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/** Replace a secret value with a short, non-reversible marker. */
export function redactValue(value: string): string {
  const shown = value.length >= 12 ? value.slice(0, 4) : '';
  return `${shown}…[redacted ${value.length} chars]`;
}

/** Stable identifier: same rule + file + normalized evidence ⇒ same id across runs. */
export function findingId(prefix: string, ruleId: string, file: string | undefined, evidence: string | undefined): string {
  const norm = (evidence ?? '').replace(/\s+/g, ' ').trim();
  return `UAR-${prefix}-${createHash('sha256').update(`${ruleId}\0${file ?? ''}\0${norm}`).digest('hex').slice(0, 12)}`;
}

export function make(prefix: string, f: Omit<Finding, 'id'>): Finding {
  return { id: findingId(prefix, f.ruleId, f.file, f.evidence), ...f };
}
