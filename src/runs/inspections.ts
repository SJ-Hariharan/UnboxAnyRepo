/**
 * Short-lived, session-bound store of inspections. Holds the sanitized source
 * archive only until it expires or memory pressure evicts it.
 */
import type { RepoMetadata } from '../github/client.ts';
import type { DetectionResult } from '../checks/types.ts';
import { newId } from './ids.ts';

export interface SourceSummary {
  fileCount: number;
  totalBytes: number;
  skippedSymlinkCount: number;
  skippedSymlinks: string[];
}

export interface Inspection {
  id: string;
  sessionId: string;
  createdAt: number;
  repo: RepoMetadata;
  commitSha: string;
  commitSource: 'default_branch' | 'url';
  /** Set in demo mode: the "commit" is a content hash of a bundled fixture. */
  demo: boolean;
  notice: string | undefined;
  source: SourceSummary;
  detection: DetectionResult;
  sanitizedTarGz: Buffer;
}

export class InspectionStore {
  private readonly items = new Map<string, Inspection>();
  private readonly ttlMs: number;
  private readonly maxBytes: number;

  constructor(opts: { ttlSec: number; maxBytes?: number }) {
    this.ttlMs = opts.ttlSec * 1000;
    this.maxBytes = opts.maxBytes ?? 512 * 1024 * 1024;
  }

  add(data: Omit<Inspection, 'id' | 'createdAt'>): Inspection {
    const item: Inspection = { ...data, id: newId(), createdAt: Date.now() };
    this.items.set(item.id, item);
    this.evict();
    return item;
  }

  /** Returns the inspection only to the session that created it. */
  get(id: string, sessionId: string): Inspection | undefined {
    const item = this.items.get(id);
    if (!item || item.sessionId !== sessionId) return undefined;
    if (Date.now() - item.createdAt > this.ttlMs) {
      this.items.delete(id);
      return undefined;
    }
    return item;
  }

  purge(): void {
    const now = Date.now();
    for (const [id, item] of this.items) if (now - item.createdAt > this.ttlMs) this.items.delete(id);
  }

  private evict(): void {
    let total = 0;
    for (const item of this.items.values()) total += item.sanitizedTarGz.length;
    // Map iteration order is insertion order: evict oldest first.
    for (const [id, item] of this.items) {
      if (total <= this.maxBytes) break;
      total -= item.sanitizedTarGz.length;
      this.items.delete(id);
    }
  }

  get size(): number {
    return this.items.size;
  }
}
