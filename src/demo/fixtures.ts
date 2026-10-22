/**
 * Demo mode: serves the small, safe repositories bundled in
 * fixtures/demo-repos/ instead of contacting GitHub. The "commit SHA" is a
 * SHA-1 of the fixture's contents and is labelled as a demo in the UI.
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { encodeEntry, endOfArchive } from '../source/tar.ts';
import { GitHubError } from '../github/client.ts';
import type { GitHubClient, RepoMetadata } from '../github/client.ts';

export const DEMO_OWNER = 'reporadar-demo';

interface DemoRepo {
  meta: RepoMetadata;
  sha: string;
  files: { path: string; data: Buffer; mode: number }[];
}

function walk(dir: string, base = ''): { path: string; data: Buffer; mode: number }[] {
  const out: { path: string; data: Buffer; mode: number }[] = [];
  for (const name of readdirSync(dir).sort()) {
    if (name === 'demo.json') continue;
    const full = path.join(dir, name);
    const rel = base ? `${base}/${name}` : name;
    const st = statSync(full);
    if (st.isDirectory()) out.push(...walk(full, rel));
    else if (st.isFile()) out.push({ path: rel, data: readFileSync(full), mode: st.mode & 0o111 ? 0o755 : 0o644 });
  }
  return out;
}

export function loadDemoRepos(root: string): Map<string, DemoRepo> {
  const repos = new Map<string, DemoRepo>();
  if (!existsSync(root)) return repos;
  for (const name of readdirSync(root).sort()) {
    const dir = path.join(root, name);
    if (!statSync(dir).isDirectory() || !/^[a-z0-9-]+$/.test(name)) continue;
    const info = JSON.parse(readFileSync(path.join(dir, 'demo.json'), 'utf8')) as { description: string; language: string | null };
    const files = walk(dir);
    const h = createHash('sha1');
    for (const f of files) h.update(f.path).update('\0').update(f.data).update('\0');
    repos.set(name, {
      sha: h.digest('hex'),
      files,
      meta: {
        owner: DEMO_OWNER,
        name,
        fullName: `${DEMO_OWNER}/${name}`,
        description: info.description,
        defaultBranch: 'main',
        language: info.language,
        htmlUrl: `https://github.com/${DEMO_OWNER}/${name}`,
        sizeKiB: Math.ceil(files.reduce((n, f) => n + f.data.length, 0) / 1024),
        archived: false,
        fork: false,
      },
    });
  }
  return repos;
}

export class FixtureGitHubClient implements GitHubClient {
  readonly kind = 'fixtures' as const;
  private readonly repos: Map<string, DemoRepo>;

  constructor(root: string) {
    this.repos = loadDemoRepos(root);
  }

  list(): RepoMetadata[] {
    return [...this.repos.values()].map((r) => r.meta);
  }

  private find(owner: string, name: string): DemoRepo {
    const r = owner.toLowerCase() === DEMO_OWNER ? this.repos.get(name.toLowerCase()) : undefined;
    if (!r) throw new GitHubError('not_found', `Demo mode only serves the bundled repositories under github.com/${DEMO_OWNER}/.`);
    return r;
  }

  async getRepo(owner: string, repo: string): Promise<RepoMetadata> {
    return this.find(owner, repo).meta;
  }

  async resolveBranch(meta: RepoMetadata): Promise<string> {
    return this.find(meta.owner, meta.name).sha;
  }

  async verifyCommit(meta: RepoMetadata, sha: string): Promise<string> {
    const r = this.find(meta.owner, meta.name);
    if (sha !== r.sha) throw new GitHubError('not_found', 'Commit not found in this demo repository.');
    return sha;
  }

  async downloadArchive(meta: RepoMetadata, sha: string): Promise<Buffer> {
    const r = this.find(meta.owner, meta.name);
    const top = `${DEMO_OWNER}-${r.meta.name}-${sha.slice(0, 7)}`;
    const parts: Buffer[] = [];
    const mtime = 1_700_000_000;
    parts.push(...encodeEntry({ path: top, kind: 'dir', mode: 0o755, mtime, uid: 0, gid: 0 }));
    const dirs = new Set<string>();
    for (const f of r.files) {
      const segs = f.path.split('/');
      for (let i = 1; i < segs.length; i++) {
        const d = segs.slice(0, i).join('/');
        if (!dirs.has(d)) {
          dirs.add(d);
          parts.push(...encodeEntry({ path: `${top}/${d}`, kind: 'dir', mode: 0o755, mtime, uid: 0, gid: 0 }));
        }
      }
      parts.push(...encodeEntry({ path: `${top}/${f.path}`, kind: 'file', mode: f.mode, mtime, uid: 0, gid: 0, data: f.data }));
    }
    parts.push(endOfArchive());
    return zlib.gzipSync(Buffer.concat(parts));
  }
}
