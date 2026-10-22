import { randomBytes } from 'node:crypto';

/** 128-bit random identifier, hex encoded. */
export function newId(): string {
  return randomBytes(16).toString('hex');
}

export function isId(v: unknown): v is string {
  return typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
}
