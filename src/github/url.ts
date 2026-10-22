/**
 * Strict parsing of user-supplied GitHub repository URLs.
 *
 * Only https://github.com/<owner>/<repo> (and a few harmless spellings of it)
 * is accepted. The host is never taken from user input: callers build API and
 * archive URLs from the validated owner/repo, so a crafted URL cannot redirect
 * our fetches anywhere else.
 */

import { hasControlChars } from '../text.ts';

export interface RepoRef {
  owner: string;
  repo: string;
  /** Canonical display URL, e.g. https://github.com/owner/repo */
  url: string;
  /** Present when the URL pinned an explicit 40-hex commit (…/tree/<sha> or …/commit/<sha>). */
  pinnedSha?: string;
  /** Human-readable notice when part of the URL was ignored. */
  notice?: string;
}

export class RepoUrlError extends Error {
  readonly code = 'invalid_url';
}

const MAX_INPUT = 512;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
const SHA_RE = /^[0-9a-f]{40}$/;

/** First path segments on github.com that are site sections, not users or orgs. */
const RESERVED_OWNERS = new Set([
  'about', 'account', 'apps', 'blog', 'codespaces', 'collections', 'contact', 'customer-stories',
  'enterprise', 'events', 'explore', 'features', 'gist', 'issues', 'join', 'login', 'logout',
  'marketplace', 'new', 'notifications', 'orgs', 'organizations', 'pricing', 'pulls', 'search',
  'security', 'settings', 'site', 'sponsors', 'topics', 'trending', 'users',
]);

export function parseRepoUrl(input: unknown): RepoRef {
  if (typeof input !== 'string') throw new RepoUrlError('Enter a GitHub repository URL.');
  const raw = input.trim();
  if (raw === '') throw new RepoUrlError('Enter a GitHub repository URL.');
  if (raw.length > MAX_INPUT) throw new RepoUrlError('That URL is too long.');
  // Reject control characters and whitespace inside the URL outright.
  if (hasControlChars(raw, { rejectSpace: true })) {
    throw new RepoUrlError('The URL contains spaces or control characters.');
  }

  let candidate = raw;
  // owner/repo shorthand
  if (/^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(candidate)) {
    candidate = `https://github.com/${candidate}`;
  } else if (/^(www\.)?github\.com\//i.test(candidate)) {
    candidate = `https://${candidate}`;
  }

  let u: URL;
  try {
    u = new URL(candidate);
  } catch {
    throw new RepoUrlError('That does not look like a URL. Example: https://github.com/owner/repo');
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    throw new RepoUrlError('Only https://github.com URLs are supported.');
  }
  if (u.username !== '' || u.password !== '') {
    throw new RepoUrlError('URLs with embedded credentials are not accepted.');
  }
  if (u.port !== '') throw new RepoUrlError('Only https://github.com URLs are supported.');
  const host = u.hostname.toLowerCase();
  if (host !== 'github.com' && host !== 'www.github.com') {
    throw new RepoUrlError('Only public repositories on github.com are supported.');
  }

  // Work on the raw (still percent-encoded) pathname so encoded slashes or dots fail the strict regexes.
  const segments = u.pathname.split('/').filter((s) => s !== '');
  if (segments.length < 2) {
    throw new RepoUrlError('Include both the owner and the repository name, e.g. https://github.com/owner/repo');
  }
  const owner = segments[0] as string;
  let repo = segments[1] as string;
  if (repo.toLowerCase().endsWith('.git')) repo = repo.slice(0, -4);

  if (!OWNER_RE.test(owner) || RESERVED_OWNERS.has(owner.toLowerCase())) {
    throw new RepoUrlError('That is not a valid GitHub owner name.');
  }
  if (!REPO_RE.test(repo) || repo === '.' || repo === '..' || repo.startsWith('.git')) {
    throw new RepoUrlError('That is not a valid GitHub repository name.');
  }

  const ref: RepoRef = { owner, repo, url: `https://github.com/${owner}/${repo}` };
  const rest = segments.slice(2);
  if (rest.length > 0) {
    const kind = rest[0];
    const target = rest[1];
    if ((kind === 'tree' || kind === 'commit') && rest.length === 2 && target !== undefined && SHA_RE.test(target)) {
      ref.pinnedSha = target;
    } else if (kind === 'tree' || kind === 'commit') {
      ref.notice =
        'Only full 40-character commit SHAs can be selected from a URL in this version, so the default branch will be used.';
    } else {
      ref.notice = 'Only the repository part of the URL was used.';
    }
  }
  return ref;
}

export function isSha(value: unknown): value is string {
  return typeof value === 'string' && SHA_RE.test(value);
}
