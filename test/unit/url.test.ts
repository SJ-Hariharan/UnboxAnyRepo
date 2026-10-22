import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRepoUrl, RepoUrlError } from '../../src/github/url.ts';

const SHA = '0123456789abcdef0123456789abcdef01234567';

test('accepts and normalizes common spellings of a repository URL', () => {
  const cases = [
    'https://github.com/nodejs/node',
    'http://github.com/nodejs/node',
    'https://www.github.com/nodejs/node',
    'https://github.com/nodejs/node/',
    'https://github.com/nodejs/node.git',
    'github.com/nodejs/node',
    'nodejs/node',
    '  https://github.com/nodejs/node  ',
    'https://github.com/nodejs/node?tab=readme-ov-file#install',
    'HTTPS://GITHUB.COM/nodejs/node',
  ];
  for (const input of cases) {
    const r = parseRepoUrl(input);
    assert.equal(r.owner, 'nodejs', input);
    assert.equal(r.repo, 'node', input);
    assert.equal(r.url, 'https://github.com/nodejs/node', input);
    assert.equal(r.pinnedSha, undefined);
  }
});

test('pins an explicit full commit SHA from /tree or /commit', () => {
  assert.equal(parseRepoUrl(`https://github.com/a/b/tree/${SHA}`).pinnedSha, SHA);
  assert.equal(parseRepoUrl(`https://github.com/a/b/commit/${SHA}`).pinnedSha, SHA);
  const branch = parseRepoUrl('https://github.com/a/b/tree/feature/x');
  assert.equal(branch.pinnedSha, undefined);
  assert.match(branch.notice ?? '', /default branch/);
  assert.match(parseRepoUrl('https://github.com/a/b/issues/3').notice ?? '', /repository part/);
});

test('rejects other hosts, look-alikes and tricks', () => {
  const bad = [
    '',
    'not a url',
    'https://gitlab.com/a/b',
    'https://github.com.evil.com/a/b',
    'https://evilgithub.com/a/b',
    'https://raw.githubusercontent.com/a/b/main/x',
    'https://api.github.com/repos/a/b',
    'https://user:pass@github.com/a/b',
    'https://github.com@evil.com/a/b',
    'https://github.com:8443/a/b',
    'ftp://github.com/a/b',
    'file:///etc/passwd',
    'javascript:alert(1)',
    'https://127.0.0.1/a/b',
    'https://[::1]/a/b',
    'https://169.254.169.254/latest/meta-data',
    'https://github.com/a',
    'https://github.com/',
    'https://github.com/settings/profile',
    'https://github.com/orgs/x',
    'https://github.com/-bad/repo',
    'https://github.com/bad-/repo',
    'https://github.com/a--b/repo',
    'https://github.com/a/..',
    'https://github.com/a/%2e%2e',
    'https://github.com/a%2fb/c',
    'https://github.com/a/b c',
    'https://github.com/a/b\nhttps://evil.com',
    'https://github.com/a/<script>',
    `https://github.com/${'a'.repeat(40)}/b`,
    `https://github.com/a/${'b'.repeat(101)}`,
    'x'.repeat(600),
  ];
  for (const input of bad) {
    assert.throws(() => parseRepoUrl(input), RepoUrlError, JSON.stringify(input));
  }
  assert.throws(() => parseRepoUrl(42 as unknown), RepoUrlError);
  assert.throws(() => parseRepoUrl(undefined as unknown), RepoUrlError);
});

test('backslash and encoded tricks cannot change the host', () => {
  // WHATWG URL treats "\" as "/" for https; the host stays github.com and the owner segment fails validation.
  assert.throws(() => parseRepoUrl('https://github.com\\@evil.com/a/b'), RepoUrlError);
  assert.throws(() => parseRepoUrl('https://github.com%2eevil.com/a/b'), RepoUrlError);
});
