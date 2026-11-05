import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeArchive } from '../../src/source/archive.ts';
import { textSkipReason, looksBinary, isSecondaryText } from '../../src/analysis/paths.ts';
import { classifySubmoduleUrl, parseGitmodules } from '../../src/analysis/gitmeta.ts';
import { checkOsv } from '../../src/analysis/osv.ts';
import type { Transport, TransportResponse } from '../../src/github/fetcher.ts';
import { markdownReport } from '../../src/report/report.ts';
import { repoArchive } from '../helpers/tarbuilder.ts';
import { analyseOffline } from '../helpers/analysis.ts';
import { InspectionStore } from '../../src/runs/inspections.ts';
import { detectProject } from '../../src/detect/index.ts';

const LIM = { maxCompressedBytes: 2e7, maxUncompressedBytes: 2e7, maxFiles: 5000, maxFileBytes: 4e6 };

async function snapshot(files: Record<string, string>) {
  const budget = 8 * 1024 * 1024;
  return sanitizeArchive(repoArchive(files), LIM, {
    collectText: { maxTotalBytes: budget, maxSecondaryBytes: Math.floor(budget / 4), isSecondary: isSecondaryText, skipReason: (p, s) => textSkipReason(p, s, 512 * 1024), isBinary: looksBinary },
  });
}

async function analyse(files: Record<string, string>) {
  return analyseOffline(await snapshot(files));
}

/** A real stored inspection, for report generation. */
async function inspection(files: Record<string, string>) {
  const snap = await snapshot(files);
  const analysis = await analyseOffline(snap);
  const insp = new InspectionStore({ ttlSec: 60 }).add({
    sessionId: 's',
    repo: { owner: 'o', name: 'r', fullName: 'o/r', description: null, defaultBranch: 'main', language: null, htmlUrl: 'https://github.com/o/r', sizeKiB: 1, archived: false, fork: false },
    commitSha: 'a'.repeat(40),
    commitSource: 'default_branch',
    demo: false,
    notice: undefined,
    source: { fileCount: snap.files.length, totalBytes: snap.totalBytes, skippedSymlinkCount: 0, skippedSymlinks: [] },
    detection: detectProject(snap, { goImage: 'golang:1.25' }),
    analysis,
    sanitizedTarGz: snap.sanitizedTarGz,
  });
  return { insp, analysis };
}

const ids = (a: { dependencies: { packages: { ecosystem: string; name: string; version: string }[] } }) =>
  a.dependencies.packages.map((p) => `${p.ecosystem}:${p.name}@${p.version}`).sort();

test('lockfiles: Bun, Bundler, Composer, NuGet and Pub give exact versions', async () => {
  const bun = `{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "app", "dependencies": { "lodash": "^4.17.0" } } },
  "packages": {
    "lodash": ["lodash@4.17.20", "", {}, "sha512-x"],
    "@types/node": ["@types/node@20.1.0", "", {}, "sha512-y"],
    "local": ["local@workspace:packages/local"],
    "gh": ["gh@github:owner/gh#abc"],
  }
}
`;
  const gemLock = `GIT
  remote: https://github.com/owner/forked.git
  revision: abc
  specs:
    forked (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.13.10-x86_64-linux)
      racc (~> 1.4)
    rack (2.2.3)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  rack
`;
  const composer = JSON.stringify({
    packages: [{ name: 'guzzlehttp/guzzle', version: '7.4.1' }, { name: 'symfony/http-kernel', version: 'v5.4.0' }, { name: 'acme/dev', version: 'dev-main' }],
    'packages-dev': [{ name: 'phpunit/phpunit', version: '9.5.10' }],
  });
  const nuget = JSON.stringify({ version: 1, dependencies: { 'net8.0': { 'Newtonsoft.Json': { type: 'Direct', resolved: '12.0.1' }, MyLib: { type: 'Project' } } } });
  const pub = 'packages:\n  http:\n    dependency: "direct main"\n    source: hosted\n    version: "0.13.3"\n  mypkg:\n    dependency: "direct main"\n    source: path\n    version: "1.0.0"\nsdks:\n  dart: ">=3.0.0 <4.0.0"\n';
  const a = await analyse({
    'package.json': '{"dependencies":{"lodash":"^4.17.0"}}',
    'bun.lock': bun,
    Gemfile: "source 'https://rubygems.org'\ngem 'rack'\n",
    'Gemfile.lock': gemLock,
    'composer.json': '{}',
    'composer.lock': composer,
    'src/App/App.csproj': '<Project Sdk="Microsoft.NET.Sdk"></Project>',
    'src/App/packages.lock.json': nuget,
    'pubspec.yaml': 'name: app\n',
    'pubspec.lock': pub,
  });
  assert.deepEqual(ids(a), [
    'NuGet:Newtonsoft.Json@12.0.1',
    'Packagist:guzzlehttp/guzzle@7.4.1',
    'Packagist:phpunit/phpunit@9.5.10',
    'Packagist:symfony/http-kernel@5.4.0',
    'Pub:http@0.13.3',
    'RubyGems:nokogiri@1.13.10',
    'RubyGems:rack@2.2.3',
    'npm:@types/node@20.1.0',
    'npm:lodash@4.17.20',
  ]);
  assert.ok(!a.dependencies.notes.some((n) => /No npm lockfile/.test(n)), 'bun.lock counts as an npm lockfile');
  for (const f of ['bun.lock', 'Gemfile.lock', 'composer.lock', 'src/App/packages.lock.json', 'pubspec.lock']) assert.ok(a.dependencies.lockfiles.includes(f), f);
});

test('lockfiles in subdirectories are read (monorepos); test fixtures are reported, not checked', async () => {
  const lock = (name: string, v: string) => JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'x' }, [`node_modules/${name}`]: { version: v }, 'packages/member': { name: 'member', version: '1.0.0' } } });
  const a = await analyse({
    'package.json': '{"workspaces":["apps/*"]}',
    'package-lock.json': lock('express', '4.17.1'),
    'apps/web/package.json': '{}',
    'apps/web/package-lock.json': lock('next', '12.0.0'),
    'test/fixtures/old/package-lock.json': lock('minimist', '0.0.8'),
  });
  assert.deepEqual(ids(a), ['npm:express@4.17.1', 'npm:next@12.0.0']);
  const web = a.dependencies.packages.find((p) => p.name === 'next');
  assert.equal(web?.source, 'apps/web/package-lock.json');
  assert.ok(a.dependencies.notes.some((n) => /1 lockfile in test fixtures was not checked/.test(n)));
});

test('missing lockfiles are explained for each ecosystem', async () => {
  const a = await analyse({ Gemfile: 'gem "rack"\n', 'composer.json': '{}', 'pubspec.yaml': 'name: x\n', 'App.csproj': '<Project/>', 'package.json': '{}', 'bun.lockb': 'binary\0' });
  const notes = a.dependencies.notes.join('\n');
  assert.match(notes, /No Gemfile\.lock/);
  assert.match(notes, /No composer\.lock/);
  assert.match(notes, /No pubspec\.lock/);
  assert.match(notes, /packages\.lock\.json/);
  assert.match(notes, /binary bun\.lockb/);
});

test('new ecosystems are sent to OSV under their OSV names', async () => {
  let body = '';
  const transport: Transport = async (url, _h, _s, b) => {
    if (b) body = b.toString();
    const out = url.pathname === '/v1/querybatch' ? { results: [{}, {}, {}, {}] } : {};
    const buf = Buffer.from(JSON.stringify(out));
    return { status: 200, headers: {}, body: (async function* () { yield buf; })(), destroy() {} } satisfies TransportResponse;
  };
  const r = await checkOsv(
    [
      { ecosystem: 'RubyGems', name: 'rack', version: '2.2.3', exact: true, source: 'Gemfile.lock' },
      { ecosystem: 'Packagist', name: 'guzzlehttp/guzzle', version: '7.4.1', exact: true, source: 'composer.lock' },
      { ecosystem: 'NuGet', name: 'Newtonsoft.Json', version: '12.0.1', exact: true, source: 'packages.lock.json' },
      { ecosystem: 'Pub', name: 'http', version: '0.13.3', exact: true, source: 'pubspec.lock' },
    ],
    { userAgent: 't', timeoutMs: 1000, transport },
  );
  assert.equal(r.tool.state, 'ran');
  const eco = (JSON.parse(body) as { queries: { package: { ecosystem: string } }[] }).queries.map((q) => q.package.ecosystem);
  assert.deepEqual(eco, ['RubyGems', 'Packagist', 'NuGet', 'Pub']);
});

test('submodule URLs are classified without contacting them', () => {
  assert.equal(classifySubmoduleUrl('https://github.com/a/b.git'), 'https');
  assert.equal(classifySubmoduleUrl('git@github.com:a/b.git'), 'ssh');
  assert.equal(classifySubmoduleUrl('ssh://git@host/a.git'), 'ssh');
  assert.equal(classifySubmoduleUrl('http://example.org/a.git'), 'http');
  assert.equal(classifySubmoduleUrl('git://example.org/a.git'), 'git-protocol');
  assert.equal(classifySubmoduleUrl('../sibling.git'), 'relative');
  assert.equal(classifySubmoduleUrl('/srv/repos/a.git'), 'local');
  assert.equal(classifySubmoduleUrl('file:///tmp/a'), 'local');
  assert.equal(classifySubmoduleUrl('ext::sh -c touch% /tmp/pwned'), 'ext-transport');
  assert.equal(classifySubmoduleUrl('-oProxyCommand=touch /tmp/pwned'), 'option-like');
  const parsed = parseGitmodules('# c\n[submodule "lib"]\n\tpath = vendor/lib\n\turl = "https://github.com/a/lib.git" ; comment\n\tbranch = main\n[core]\n\turl = ignored\n');
  assert.deepEqual(parsed, [{ name: 'lib', path: 'vendor/lib', url: 'https://github.com/a/lib.git', branch: 'main', line: 2 }]);
});

test('submodules are listed, and dangerous or insecure URLs become findings', async () => {
  const gitmodules = [
    '[submodule "ok"]', '  path = libs/ok', '  url = https://github.com/a/ok.git',
    '[submodule "plain"]', '  path = libs/plain', '  url = http://example.org/plain.git',
    '[submodule "ext"]', '  path = libs/ext', '  url = ext::sh -c id',
    '[submodule "dash"]', '  path = libs/dash', '  url = -oProxyCommand=id',
    '[submodule "key"]', '  path = libs/key', '  url = git@github.com:a/key.git',
    '',
  ].join('\n');
  const { insp, analysis: a } = await inspection({ '.gitmodules': gitmodules, 'README.md': '# x\n' });
  assert.deepEqual(a.git.submodules.map((s) => `${s.name}:${s.urlKind}`), ['ok:https', 'plain:http', 'ext:ext-transport', 'dash:option-like', 'key:ssh']);
  const byRule = Object.fromEntries(a.findings.filter((f) => f.ruleId.startsWith('git.')).map((f) => [f.ruleId, f]));
  assert.equal(byRule['git.submodule-url-option']?.severity, 'high');
  assert.equal(byRule['git.submodule-ext-transport']?.severity, 'high');
  assert.equal(byRule['git.submodule-insecure-transport']?.severity, 'medium');
  assert.equal(byRule['git.submodule-ssh']?.status, 'informational');
  assert.equal(byRule['git.submodule-insecure-transport']?.file, '.gitmodules');
  assert.equal(byRule['git.submodule-insecure-transport']?.startLine, 6, 'points at the url line');
  assert.ok(!a.findings.some((f) => f.evidence?.includes('github.com/a/ok')), 'https submodules are not findings');
  const report = markdownReport(insp, 'UnboxAnyRepo');
  assert.match(report, /## Git submodules/);
  assert.match(report, /libs\/plain/);
});

test('Git LFS pointer files are found, even with binary extensions; real binaries are not', async () => {
  const oid = 'a'.repeat(64);
  const a = await analyse({
    '.gitattributes': '# assets\n*.psd filter=lfs diff=lfs merge=lfs -text\nmodels/** filter=lfs diff=lfs merge=lfs -text\n*.txt text\n',
    'art/cover.psd': `version https://git-lfs.github.com/spec/v1\noid sha256:${oid}\nsize 52428800\n`,
    'models/weights.bin': `version https://git-lfs.github.com/spec/v1\noid sha256:${'b'.repeat(64)}\nsize 1024\n`,
    'img/real.png': '\x89PNG\r\n\x1a\n\0\0\0\rIHDR',
    'notes.txt': 'version https://git-lfs is mentioned here but this is not a pointer\n',
  });
  assert.deepEqual(a.git.lfs.patterns, ['*.psd', 'models/**']);
  assert.equal(a.git.lfs.pointerCount, 2);
  assert.equal(a.git.lfs.pointerBytes, 52428800 + 1024);
  assert.deepEqual(a.git.lfs.pointers.map((p) => p.path), ['art/cover.psd', 'models/weights.bin']);
  const msgs = a.compatibility.map((c) => c.message).join('\n');
  assert.match(msgs, /2 files are Git LFS pointers \(50\.0 MB/);
});
