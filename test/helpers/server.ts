import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AddressInfo } from 'node:net';
import { createApp } from '../../src/app.ts';
import type { App } from '../../src/app.ts';
import { FixtureGitHubClient } from '../../src/demo/fixtures.ts';
import type { GitHubClient } from '../../src/github/client.ts';
import type { Runner } from '../../src/runner/types.ts';
import { testConfig } from './limits.ts';
import { FakeRunner } from './fake-runner.ts';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const DEMO = (name: string) => `https://github.com/reporadar-demo/${name}`;

export interface TestServer {
  app: App;
  base: string;
  runner: Runner;
  logs: string[];
  close(): Promise<void>;
}

export async function startServer(opts: { env?: Record<string, string>; runner?: Runner; github?: GitHubClient } = {}): Promise<TestServer> {
  const config = testConfig(opts.env ?? {});
  const runner = opts.runner ?? new FakeRunner();
  const github = opts.github ?? new FixtureGitHubClient(path.join(ROOT, 'fixtures', 'demo-repos'));
  const logs: string[] = [];
  const app = createApp({ config, github, runner, log: (m) => logs.push(m) });
  await new Promise<void>((r) => app.server.listen(0, '127.0.0.1', r));
  const { port } = app.server.address() as AddressInfo;
  return { app, base: `http://127.0.0.1:${port}`, runner, logs, close: () => app.close() };
}

/** Minimal client with its own cookie (i.e. its own browser session). */
export class Client {
  cookie = '';
  readonly base: string;
  constructor(base: string) {
    this.base = base;
  }
  async req(p: string, init: { method?: string; json?: unknown; headers?: Record<string, string>; body?: string } = {}) {
    const headers: Record<string, string> = { ...(init.headers ?? {}) };
    if (this.cookie) headers.cookie = this.cookie;
    let body = init.body;
    if (init.json !== undefined) {
      headers['content-type'] ??= 'application/json';
      body = JSON.stringify(init.json);
    }
    const res = await fetch(this.base + p, { method: init.method ?? (body !== undefined ? 'POST' : 'GET'), headers, ...(body !== undefined ? { body } : {}) });
    const set = res.headers.get('set-cookie');
    if (set) this.cookie = set.split(';')[0] as string;
    return res;
  }
  async json(p: string, init: Parameters<Client['req']>[1] = {}) {
    const res = await this.req(p, init);
    const text = await res.text();
    let data: any = null;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
    return { status: res.status, data, headers: res.headers };
  }
}
