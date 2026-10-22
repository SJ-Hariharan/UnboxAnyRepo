import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpGitHubClient, GitHubError, parseRepoMetadata, isSafeBranchName } from '../../src/github/client.ts';
import type { Transport } from '../../src/github/fetcher.ts';

const SHA = 'c'.repeat(40);

function routes(map: Record<string, { status: number; headers?: Record<string, string>; body?: string }>, seen: string[] = []): Transport {
  return async (url, headers) => {
    seen.push(`${url.toString()} auth=${headers.authorization ?? '-'}`);
    const r = map[url.toString()];
    if (!r) return { status: 404, headers: {}, body: (async function* () {})(), destroy() {} };
    return {
      status: r.status,
      headers: r.headers ?? {},
      body: (async function* () {
        if (r.body !== undefined) yield Buffer.from(r.body);
      })(),
      destroy() {},
    };
  };
}

const repoJson = (over: Record<string, unknown> = {}) =>
  JSON.stringify({
    full_name: 'octo/demo',
    private: false,
    visibility: 'public',
    description: 'A demo',
    default_branch: 'main',
    language: 'TypeScript',
    size: 120,
    archived: false,
    fork: false,
    ...over,
  });

test('fetches metadata, resolves the default branch, and downloads only from codeload', async () => {
  const seen: string[] = [];
  const client = new HttpGitHubClient({
    userAgent: 'test',
    timeoutMs: 1000,
    token: 'ghp_secretsecretsecret',
    transport: routes(
      {
        'https://api.github.com/repos/octo/demo': { status: 200, body: repoJson() },
        'https://api.github.com/repos/octo/demo/git/ref/heads/main': { status: 200, body: JSON.stringify({ object: { sha: SHA, type: 'commit' } }) },
        [`https://codeload.github.com/octo/demo/tar.gz/${SHA}`]: { status: 200, body: 'TARBALL' },
      },
      seen,
    ),
  });
  const meta = await client.getRepo('octo', 'demo');
  assert.equal(meta.fullName, 'octo/demo');
  assert.equal(meta.htmlUrl, 'https://github.com/octo/demo');
  assert.equal(await client.resolveBranch(meta, meta.defaultBranch), SHA);
  assert.equal((await client.downloadArchive(meta, SHA, 1000)).toString(), 'TARBALL');
  // The token is sent to the API host only, never to codeload.
  assert.match(seen[0] ?? '', /auth=Bearer/);
  assert.match(seen[2] ?? '', /codeload.*auth=-$/);
});

test('follows the API redirect for a renamed repository', async () => {
  const client = new HttpGitHubClient({
    userAgent: 't',
    timeoutMs: 1000,
    transport: routes({
      'https://api.github.com/repos/old/name': { status: 301, headers: { location: 'https://api.github.com/repositories/42' } },
      'https://api.github.com/repositories/42': { status: 200, body: repoJson({ full_name: 'new/name' }) },
    }),
  });
  assert.equal((await client.getRepo('old', 'name')).fullName, 'new/name');
});

test('maps GitHub failures to safe error codes', async () => {
  const make = (status: number, headers: Record<string, string> = {}) =>
    new HttpGitHubClient({ userAgent: 't', timeoutMs: 1000, transport: routes({ 'https://api.github.com/repos/a/b': { status, headers, body: '{}' } }) });
  await assert.rejects(make(404).getRepo('a', 'b'), (e: unknown) => e instanceof GitHubError && e.code === 'not_found');
  await assert.rejects(make(451).getRepo('a', 'b'), (e: unknown) => e instanceof GitHubError && e.code === 'unavailable');
  await assert.rejects(make(500).getRepo('a', 'b'), (e: unknown) => e instanceof GitHubError && e.code === 'upstream');
  const reset = String(Math.round(Date.now() / 1000) + 120);
  await assert.rejects(make(403, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': reset }).getRepo('a', 'b'), (e: unknown) => {
    assert.ok(e instanceof GitHubError);
    assert.equal(e.code, 'rate_limited');
    assert.ok((e.retryAfterSec ?? 0) > 60 && (e.retryAfterSec ?? 0) <= 120);
    return true;
  });
  await assert.rejects(make(429, { 'retry-after': '30' }).getRepo('a', 'b'), (e: unknown) => e instanceof GitHubError && e.retryAfterSec === 30);
});

test('refuses private or non-public repositories even if the API returns them', () => {
  assert.throws(() => parseRepoMetadata(JSON.parse(repoJson({ private: true }))), (e: unknown) => e instanceof GitHubError && e.code === 'not_public');
  assert.throws(() => parseRepoMetadata(JSON.parse(repoJson({ visibility: 'internal' }))), (e: unknown) => e instanceof GitHubError && e.code === 'not_public');
  assert.throws(() => parseRepoMetadata(JSON.parse(repoJson({ private: undefined }))), GitHubError);
});

test('treats metadata as hostile: validates names, branch, and cleans text', () => {
  assert.throws(() => parseRepoMetadata(JSON.parse(repoJson({ full_name: '../../evil' }))), GitHubError);
  assert.throws(() => parseRepoMetadata(JSON.parse(repoJson({ full_name: 'a/b/c' }))), GitHubError);
  assert.throws(() => parseRepoMetadata(JSON.parse(repoJson({ default_branch: 'main..x' }))), GitHubError);
  assert.throws(() => parseRepoMetadata(null), GitHubError);
  const m = parseRepoMetadata(JSON.parse(repoJson({ description: `line1\n\u001b[31mred\u0000 <b>x</b>${'y'.repeat(500)}`, language: 42 })));
  assert.ok(m.description !== null && m.description.length <= 300);
  assert.equal(m.description?.includes('\n'), false);
  assert.equal(m.language, null);
  // html_url is always built by us, never taken from the response
  assert.equal(parseRepoMetadata(JSON.parse(repoJson({ html_url: 'javascript:alert(1)' }))).htmlUrl, 'https://github.com/octo/demo');
});

test('branch name validation', () => {
  for (const ok of ['main', 'release/1.2', 'feature-x', 'v1.0']) assert.equal(isSafeBranchName(ok), true, ok);
  for (const bad of ['', 'a..b', '/x', 'x/', 'a b', 'a~1', 'a^', 'a:b', 'x.lock', 'a//b', 'a@{1}', 'a\\b', 'x'.repeat(256)]) {
    assert.equal(isSafeBranchName(bad), false, bad);
  }
});

test('rejects a malformed commit response', async () => {
  const meta = parseRepoMetadata(JSON.parse(repoJson()));
  const client = new HttpGitHubClient({
    userAgent: 't',
    timeoutMs: 1000,
    transport: routes({
      'https://api.github.com/repos/octo/demo/git/ref/heads/main': { status: 200, body: JSON.stringify({ object: { sha: 'nope', type: 'commit' } }) },
      [`https://api.github.com/repos/octo/demo/commits/${SHA}`]: { status: 200, body: `${SHA}\n` },
    }),
  });
  await assert.rejects(client.resolveBranch(meta, 'main'), GitHubError);
  assert.equal(await client.verifyCommit(meta, SHA), SHA);
  await assert.rejects(client.verifyCommit(meta, 'HEAD'), GitHubError);
});
