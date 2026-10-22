/** In-memory sliding-window rate limiter keyed by client (IP or session). */
export class RateLimiter {
  private readonly hits = new Map<string, number[]>();
  private readonly limit: number;
  private readonly windowMs: number;
  private readonly maxKeys: number;

  constructor(limit: number, windowMs: number, maxKeys = 50_000) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.maxKeys = maxKeys;
  }

  /** Records a hit if allowed. Returns 0 when allowed, otherwise seconds to wait. */
  take(key: string, now = Date.now()): number {
    const cutoff = now - this.windowMs;
    const list = (this.hits.get(key) ?? []).filter((t) => t > cutoff);
    if (list.length >= this.limit) {
      this.hits.set(key, list);
      return Math.max(1, Math.ceil(((list[0] as number) + this.windowMs - now) / 1000));
    }
    list.push(now);
    this.hits.delete(key); // re-insert to keep Map order ≈ LRU
    this.hits.set(key, list);
    if (this.hits.size > this.maxKeys) {
      const oldest = this.hits.keys().next().value;
      if (oldest !== undefined) this.hits.delete(oldest);
    }
    return 0;
  }

  /** Seconds to wait if the next hit would be refused, else 0. Does not record a hit. */
  peek(key: string, now = Date.now()): number {
    const cutoff = now - this.windowMs;
    const list = (this.hits.get(key) ?? []).filter((t) => t > cutoff);
    if (list.length < this.limit) return 0;
    return Math.max(1, Math.ceil(((list[0] as number) + this.windowMs - now) / 1000));
  }

  purge(now = Date.now()): void {
    const cutoff = now - this.windowMs;
    for (const [k, list] of this.hits) {
      const kept = list.filter((t) => t > cutoff);
      if (kept.length === 0) this.hits.delete(k);
      else this.hits.set(k, kept);
    }
  }
}
