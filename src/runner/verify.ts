/**
 * Sandbox verification.
 *
 * Execution with the strong runtime is allowed only when BOTH hold:
 *
 *   1. a live probe shows that the runtime registered as "runsc" really is
 *      gVisor (its kernel log identifies itself), and
 *   2. a verification record exists that `npm run sandbox -- --verify` wrote
 *      after every required real-container test passed against the same
 *      Docker host, runtime and image IDs, and it is not older than the
 *      configured maximum age.
 *
 * Neither can be satisfied by setting environment variables. The record is
 * evidence of a past test run, not a guarantee; it is invalidated whenever an
 * image changes.
 */
import { readFileSync } from 'node:fs';
import type { Ecosystem } from '../config.ts';

export const ATTESTATION_SCHEMA = 'unboxanyrepo.sandbox-verification/v1';

export type CheckStatus = 'PASS' | 'FAIL' | 'BLOCKED' | 'NOT RUN' | 'UNKNOWN';

export interface Attestation {
  schema: typeof ATTESTATION_SCHEMA;
  createdAt: string;
  runtime: 'runsc';
  dockerHost: string | null;
  dockerServerVersion: string;
  gvisorProbe: string;
  images: Partial<Record<Ecosystem, { ref: string; id: string }>>;
  tests: { name: string; status: CheckStatus }[];
  allRequiredPassed: boolean;
}

export interface VerificationOptions {
  /** Require a verification record (always true outside tests and the verification command). */
  required: boolean;
  file: string;
  maxAgeDays: number;
}

const ID_RE = /^sha256:[a-f0-9]{64}$|^sha256:[a-z0-9]{1,64}$/;

export function parseAttestation(json: unknown): Attestation | undefined {
  if (typeof json !== 'object' || json === null) return undefined;
  const a = json as Record<string, unknown>;
  if (a.schema !== ATTESTATION_SCHEMA || a.runtime !== 'runsc' || typeof a.createdAt !== 'string' || Number.isNaN(Date.parse(a.createdAt))) return undefined;
  if (a.allRequiredPassed !== true || !Array.isArray(a.tests) || a.tests.length === 0) return undefined;
  if (!a.tests.every((t) => typeof t === 'object' && t !== null && typeof (t as { name?: unknown }).name === 'string' && (t as { status?: unknown }).status === 'PASS')) return undefined;
  if (typeof a.images !== 'object' || a.images === null) return undefined;
  for (const v of Object.values(a.images as Record<string, unknown>)) {
    const img = v as { ref?: unknown; id?: unknown } | null;
    if (!img || typeof img.ref !== 'string' || typeof img.id !== 'string' || !ID_RE.test(img.id)) return undefined;
  }
  if (a.dockerHost !== null && typeof a.dockerHost !== 'string') return undefined;
  return a as unknown as Attestation;
}

export function loadAttestation(file: string): Attestation | undefined {
  try {
    return parseAttestation(JSON.parse(readFileSync(file, 'utf8')));
  } catch {
    return undefined;
  }
}

export interface CurrentSandbox {
  dockerHost: string | null;
  imageIds: Partial<Record<Ecosystem, string>>;
}

/** Ecosystems whose current image matches the verified one; or a reason nothing is usable. */
export function checkAttestation(att: Attestation | undefined, cur: CurrentSandbox, maxAgeDays: number, now = Date.now()): { ok: Ecosystem[]; reason?: string } {
  const how = 'Run "npm run sandbox -- --verify" on the sandbox host to run the real-container tests and record the result.';
  if (!att) return { ok: [], reason: `The sandbox has not been verified, so execution is disabled. ${how}` };
  const ageDays = (now - Date.parse(att.createdAt)) / 86_400_000;
  if (ageDays > maxAgeDays) return { ok: [], reason: `The sandbox verification is older than ${maxAgeDays} days, so execution is disabled. ${how}` };
  if ((att.dockerHost ?? null) !== (cur.dockerHost ?? null)) return { ok: [], reason: `The sandbox was verified against a different Docker host, so execution is disabled. ${how}` };
  const ok: Ecosystem[] = [];
  for (const [eco, id] of Object.entries(cur.imageIds) as [Ecosystem, string][]) {
    if (att.images[eco]?.id === id) ok.push(eco);
  }
  if (ok.length === 0) return { ok, reason: `No sandbox image matches the verified images (an image was changed or re-pulled), so execution is disabled. ${how}` };
  return { ok };
}

/** True when kernel-log output identifies gVisor. */
export function isGvisorKernelLog(text: string): boolean {
  return /\bgVisor\b/.test(text);
}
