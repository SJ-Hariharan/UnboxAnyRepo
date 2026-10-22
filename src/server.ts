/**
 * Entry point. Loads configuration, wires the GitHub source and runner, and
 * starts the HTTP server. Run with `npm start`, or `npm run demo` for the
 * offline demo that serves bundled fixture repositories.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig, ConfigError } from './config.ts';
import { HttpGitHubClient } from './github/client.ts';
import { configureOutboundProxy } from './github/fetcher.ts';
import { FixtureGitHubClient } from './demo/fixtures.ts';
import { createRunner } from './runner/factory.ts';
import { createApp } from './app.ts';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig(process.env, process.argv.slice(2));
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(`Configuration error: ${err.message}`);
      process.exit(2);
    }
    throw err;
  }

  configureOutboundProxy(config.outboundProxy);
  const github =
    config.githubSource === 'fixtures'
      ? new FixtureGitHubClient(path.join(ROOT, 'fixtures', 'demo-repos'))
      : new HttpGitHubClient({
          ...(config.githubToken ? { token: config.githubToken } : {}),
          userAgent: config.userAgent,
          timeoutMs: config.limits.fetchTimeoutMs,
        });
  const runner = createRunner(config);
  const app = createApp({ config, github, runner });
  const status = await runner.status(true);

  app.server.listen(config.port, config.host, () => {
    const addr = app.server.address();
    const port = typeof addr === 'object' && addr ? addr.port : config.port;
    console.log(`${config.productName} listening on http://${config.host}:${port}`);
    console.log(`  source:    ${config.githubSource === 'fixtures' ? 'bundled demo fixtures (GitHub is not contacted)' : 'github.com'}`);
    console.log(`  execution: ${status.available ? status.label : `disabled — ${status.reason ?? 'unavailable'}`}`);
    if (status.isolation === 'unsafe-local') {
      console.warn('  WARNING: runc is NOT a strong sandbox. Never expose this instance to other people.');
    }
  });

  const shutdown = () => {
    void app.close().then(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

void main();
