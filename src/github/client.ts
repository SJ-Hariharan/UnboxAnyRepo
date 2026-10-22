/**
 * GitHub access: repository metadata, commit resolution, source archive.
 *
 * All URLs are built from validated owner/repo/sha values; the only hosts ever
 * contacted are api.github.com and codeload.github.com. A configured token is
 * sent only to api.github.com and never reaches the sandbox. Responses are
 * treated as untrusted: every field we use is type- and format-checked.
 */
import { safeFetch, FetchError } from './fetcher.ts';
import type { Transport } from './fetcher.ts';
import { isSha } from './url.ts';
import { collapseControlChars, hasControlChars } from '../text.ts';

export interface RepoMetadata {
  owner: string;
  name: string;
  fullName: string;
  description: string | null;
  defaultBranch: string;
  language: string | null;
  htmlUrl: string;
  sizeKiB: number;
  archived: boolean;
  fork: boolean;
}

export type GitHubErrorCode =
  | 'not_found'
  | 'not_public'
  | 'rate_limited'
  | 'unavailable'
  | 'too_large'
  | 'upstream'
  | 'timeout'
  | 'network';

export class GitHubError extends Error {
  readonly code: GitHubErrorCode;
  readonly retryAfterSec: number | undefined;
  constructor(code: GitHubErrorCode, message: string, retryAfterSec?: number) {
    super(message);
    this.code = code;
    this.retryAfterSec = retryAfterSec;
  }
}

export interface GitHubClient {
  readonly kind: 'live' | 'fixtures';
  getRepo(owner: string, repo: string, signal?: AbortSignal): Promise<RepoMetadata>;
  /** Resolve a branch name to a commit SHA. */
  resolveBranch(meta: RepoMetadata, branch: string, signal?: AbortSignal): Promise<string>;
  /** Confirm a user-supplied SHA exists for this repository. */
  verifyCommit(meta: RepoMetadata, sha: string, signal?: AbortSignal): Promise<string>;
  downloadArchive(meta: RepoMetadata, sha: string, maxBytes: number, signal?: AbortSignal): Promise<Buffer>;
}

const API_HOSTS = new Set(['api.github.com']);
const ARCHIVE_HOSTS = new Set(['codeload.github.com']);
const NAME_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;

export interface HttpGitHubClientOptions {
  token?: string;
  userAgent: string;
  timeoutMs: number;
  transport?: Transport;
}

function cleanText(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  // Strip control characters (keep it single-line) and cap length.
  const t = collapseControlChars(value).trim();
  if (t === '') return null;
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/** Validate a git branch name enough to use it as a URL path. */
export function isSafeBranchName(b: string): boolean {
  return (
    b.length > 0 &&
    b.length <= 255 &&
    !hasControlChars(b, { rejectSpace: true }) &&
    !/[~^:?*[\\]/.test(b) &&
    !b.includes('..') &&
    !b.startsWith('/') &&
    !b.endsWith('/') &&
    !b.endsWith('.lock') &&
    !b.includes('//') &&
    !b.includes('@{')
  );
}

export function parseRepoMetadata(json: unknown): RepoMetadata {
  if (typeof json !== 'object' || json === null) throw new GitHubError('upstream', 'Unexpected response from GitHub');
  const o = json as Record<string, unknown>;
  const fullName = typeof o.full_name === 'string' ? o.full_name : '';
  const [owner, name, extra] = fullName.split('/');
  if (!owner || !name || extra !== undefined || !NAME_RE.test(owner) || !REPO_RE.test(name)) {
    throw new GitHubError('upstream', 'Unexpected response from GitHub');
  }
  // Only public repositories. A configured token might otherwise expose private ones.
  if (o.private !== false || (o.visibility !== undefined && o.visibility !== 'public')) {
    throw new GitHubError('not_public', 'This repository is not public.');
  }
  const defaultBranch = typeof o.default_branch === 'string' ? o.default_branch : '';
  if (!isSafeBranchName(defaultBranch)) throw new GitHubError('upstream', 'Repository default branch could not be used');
  const sizeKiB = typeof o.size === 'number' && Number.isFinite(o.size) && o.size >= 0 ? o.size : 0;
  return {
    owner,
    name,
    fullName: `${owner}/${name}`,
    description: cleanText(o.description, 300),
    defaultBranch,
    language: cleanText(o.language, 40),
    htmlUrl: `https://github.com/${owner}/${name}`,
    sizeKiB,
    archived: o.archived === true,
    fork: o.fork === true,
  };
}

function header(h: Record<string, string | string[] | undefined>, key: string): string | undefined {
  const v = h[key];
  return Array.isArray(v) ? v[0] : v;
}

export class HttpGitHubClient implements GitHubClient {
  readonly kind = 'live' as const;
  private readonly opts: HttpGitHubClientOptions;

  constructor(opts: HttpGitHubClientOptions) {
    this.opts = opts;
  }

  private async api(path: string, accept: string, signal?: AbortSignal, maxBytes = 1024 * 1024) {
    try {
      const res = await safeFetch(`https://api.github.com${path}`, {
        allowedHosts: API_HOSTS,
        headers: {
          accept,
          'user-agent': this.opts.userAgent,
          'x-github-api-version': '2022-11-28',
        },
        ...(this.opts.token ? { sensitiveHeaders: { authorization: `Bearer ${this.opts.token}` } } : {}),
        maxBytes,
        timeoutMs: this.opts.timeoutMs,
        maxRedirects: 2,
        ...(signal ? { signal } : {}),
        ...(this.opts.transport ? { transport: this.opts.transport } : {}),
      });
      this.raiseForStatus(res.status, res.headers as Record<string, string | string[] | undefined>);
      return res;
    } catch (err) {
      throw toGitHubError(err);
    }
  }

  private raiseForStatus(status: number, headers: Record<string, string | string[] | undefined>): void {
    if (status >= 200 && status < 300) return;
    const remaining = header(headers, 'x-ratelimit-remaining');
    const retryAfter = Number(header(headers, 'retry-after'));
    const reset = Number(header(headers, 'x-ratelimit-reset'));
    if (status === 429 || (status === 403 && (remaining === '0' || Number.isFinite(retryAfter)))) {
      let wait: number | undefined;
      if (Number.isFinite(retryAfter) && retryAfter > 0) wait = Math.min(retryAfter, 3600);
      else if (Number.isFinite(reset) && reset > 0) wait = Math.max(1, Math.min(3600, Math.round(reset - Date.now() / 1000)));
      throw new GitHubError('rate_limited', 'GitHub rate limit reached. Try again later.', wait);
    }
    if (status === 404) throw new GitHubError('not_found', 'Repository not found. It may be private, renamed, or deleted.');
    if (status === 451 || status === 403) throw new GitHubError('unavailable', 'GitHub is not serving this repository.');
    if (status === 409) throw new GitHubError('unavailable', 'This repository is empty.');
    throw new GitHubError('upstream', 'GitHub returned an unexpected response.');
  }

  async getRepo(owner: string, repo: string, signal?: AbortSignal): Promise<RepoMetadata> {
    const res = await this.api(`/repos/${owner}/${repo}`, 'application/vnd.github+json', signal);
    let json: unknown;
    try {
      json = JSON.parse(res.body.toString('utf8'));
    } catch {
      throw new GitHubError('upstream', 'Unexpected response from GitHub');
    }
    return parseRepoMetadata(json);
  }

  async resolveBranch(meta: RepoMetadata, branch: string, signal?: AbortSignal): Promise<string> {
    if (!isSafeBranchName(branch)) throw new GitHubError('upstream', 'Branch name could not be used');
    const encoded = branch.split('/').map(encodeURIComponent).join('/');
    const res = await this.api(`/repos/${meta.fullName}/git/ref/heads/${encoded}`, 'application/vnd.github+json', signal);
    let json: unknown;
    try {
      json = JSON.parse(res.body.toString('utf8'));
    } catch {
      throw new GitHubError('upstream', 'Unexpected response from GitHub');
    }
    const obj = (json as { object?: { sha?: unknown; type?: unknown } } | null)?.object;
    if (!obj || obj.type !== 'commit' || !isSha(obj.sha)) {
      throw new GitHubError('upstream', 'Could not resolve the default branch to a commit');
    }
    return obj.sha;
  }

  async verifyCommit(meta: RepoMetadata, sha: string, signal?: AbortSignal): Promise<string> {
    if (!isSha(sha)) throw new GitHubError('not_found', 'Commit not found');
    const res = await this.api(`/repos/${meta.fullName}/commits/${sha}`, 'application/vnd.github.sha', signal, 1024);
    const body = res.body.toString('utf8').trim();
    if (!isSha(body)) throw new GitHubError('upstream', 'Unexpected response from GitHub');
    return body;
  }

  async downloadArchive(meta: RepoMetadata, sha: string, maxBytes: number, signal?: AbortSignal): Promise<Buffer> {
    if (!isSha(sha)) throw new GitHubError('upstream', 'Invalid commit');
    try {
      const res = await safeFetch(`https://codeload.github.com/${meta.fullName}/tar.gz/${sha}`, {
        allowedHosts: ARCHIVE_HOSTS,
        headers: { 'user-agent': this.opts.userAgent, accept: 'application/x-gzip, application/octet-stream' },
        maxBytes,
        timeoutMs: this.opts.timeoutMs,
        maxRedirects: 1,
        ...(signal ? { signal } : {}),
        ...(this.opts.transport ? { transport: this.opts.transport } : {}),
      });
      this.raiseForStatus(res.status, res.headers as Record<string, string | string[] | undefined>);
      return res.body;
    } catch (err) {
      throw toGitHubError(err);
    }
  }
}

export function toGitHubError(err: unknown): GitHubError {
  if (err instanceof GitHubError) return err;
  if (err instanceof FetchError) {
    switch (err.code) {
      case 'too_large':
        return new GitHubError('too_large', 'The repository archive is larger than this deployment allows.');
      case 'timeout':
        return new GitHubError('timeout', 'GitHub did not respond in time.');
      default:
        return new GitHubError('network', 'Could not reach GitHub.');
    }
  }
  return new GitHubError('network', 'Could not reach GitHub.');
}
