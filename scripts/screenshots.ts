/**
 * Capture README screenshots from the demo fixtures.
 *
 * Uses the scripted test runner, so NO code is executed and the run output in
 * the images is sample text. The README captions say so.
 *
 *   PLAYWRIGHT_BROWSERS_PATH=... node scripts/screenshots.ts [outDir]
 */
import path from 'node:path';
import { mkdirSync } from 'node:fs';
import { chromium } from 'playwright';
import type { Page } from 'playwright';
import { startServer, DEMO, ROOT } from '../test/helpers/server.ts';
import { FakeRunner } from '../test/helpers/fake-runner.ts';

const out = path.resolve(process.argv[2] ?? path.join(ROOT, 'docs', 'screenshots'));
mkdirSync(out, { recursive: true });

const runner = new FakeRunner();
runner.statusOverride = { label: 'scripted demo runner (nothing executed)' };
const srv = await startServer({ runner });
const browser = await chromium.launch();

async function flow(page: Page, repo: string, check: RegExp) {
  await page.goto(srv.base);
  await page.getByText(/Sandbox ready|Execution disabled/).waitFor();
  await page.getByLabel('Public GitHub repository URL').fill(DEMO(repo));
  await page.getByRole('button', { name: 'Inspect' }).click();
  await page.locator('#inspection').waitFor();
  await page.getByRole('radio', { name: check }).check();
  await page.getByLabel(/I understand that code from/).check();
}

try {
  for (const scheme of ['light', 'dark'] as const) {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, colorScheme: scheme, deviceScaleFactor: 1 });
    await page.goto(srv.base);
    await page.getByText(/Sandbox ready/).waitFor();
    await page.screenshot({ path: path.join(out, `home-${scheme}.png`) });

    await page.getByLabel('Public GitHub repository URL').fill(DEMO('risky-node-api'));
    await page.getByRole('button', { name: 'Inspect' }).click();
    await page.locator('#inspection').waitFor();
    await page.locator('#findings .finding summary').nth(1).click();
    await page.locator('#sec-security').screenshot({ path: path.join(out, `security-${scheme}.png`) });
    await page.locator('#sec-overview').screenshot({ path: path.join(out, `overview-${scheme}.png`) });

    await page.getByLabel('Public GitHub repository URL').fill(DEMO('flask-app'));
    await page.getByRole('button', { name: 'Inspect' }).click();
    await page.locator('#setup').getByText('Start Flask').waitFor();
    await page.locator('#sec-setup').screenshot({ path: path.join(out, `setup-${scheme}.png`) });

    await page.getByLabel('Public GitHub repository URL').fill(DEMO('static-site'));
    await page.getByRole('button', { name: 'Inspect' }).click();
    await page.getByRole('button', { name: 'Start preview' }).click();
    await page.frameLocator('.preview-frame').locator('#result').waitFor();
    await page.locator('#sec-preview').screenshot({ path: path.join(out, `preview-${scheme}.png`) });

    await flow(page, 'node-hello', /npm test/);
    await page.locator('#sec-checks').screenshot({ path: path.join(out, `plan-${scheme}.png`) });

    runner.script = {
      lines: [
        '▶ add\n', '✔ add (0.6ms)\n', '▶ mean\n', '✔ mean (0.4ms)\n',
        'ℹ tests 2\n', 'ℹ pass 2\n', 'ℹ fail 0\n', 'ℹ duration_ms 41.2\n',
      ],
      delayMs: 400,
    };
    await page.getByRole('button', { name: 'Start check' }).click();
    await page.locator('#run-result').waitFor();
    await page.locator('#run').scrollIntoViewIfNeeded();
    await page.locator('#run').screenshot({ path: path.join(out, `run-${scheme}.png`) });
    await page.close();
  }

  const mobile = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  runner.script = { lines: ['running…\n'], hang: true };
  await flow(mobile, 'go-hello', /go test/);
  await mobile.getByRole('button', { name: 'Start check' }).click();
  await mobile.locator('#chamber[data-active="true"]').waitFor();
  await mobile.locator('#run').scrollIntoViewIfNeeded();
  await mobile.screenshot({ path: path.join(out, 'mobile-running.png') });
  await mobile.getByRole('button', { name: 'Cancel run' }).click();
  await mobile.close();
  console.log(`Screenshots written to ${out}`);
} finally {
  await browser.close();
  await srv.close();
}
