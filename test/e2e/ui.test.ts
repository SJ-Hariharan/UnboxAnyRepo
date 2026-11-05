/// <reference lib="dom" />
/**
 * Browser tests against the real UI and API, using bundled demo fixtures and
 * a scripted test runner (nothing is executed). Requires Playwright's Chromium.
 */
import { test, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import type { Browser, Page } from 'playwright';
import { startServer, DEMO } from '../helpers/server.ts';
import type { TestServer } from '../helpers/server.ts';
import { FakeRunner } from '../helpers/fake-runner.ts';

let browser: Browser;
let srv: TestServer;
let runner: FakeRunner;

before(async () => {
  runner = new FakeRunner();
  srv = await startServer({ runner });
  browser = await chromium.launch();
});
// A failed test must not leave a hanging scripted run behind for the next one.
afterEach(() => runner.reset());
after(async () => {
  await browser?.close();
  await srv?.close();
});

async function open(base = srv.base, opts: Parameters<Browser['newPage']>[0] = {}): Promise<Page> {
  const page = await browser.newPage(opts);
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  (page as unknown as { __errors: string[] }).__errors = errors;
  await page.goto(base);
  await page.getByText(/Sandbox ready|Execution disabled/).waitFor();
  return page;
}

/** Page overflow in px, and the outermost elements that stick out past the viewport (for failure messages). */
async function horizontalOverflow(page: Page): Promise<{ px: number; culprits: string }> {
  return page.evaluate(() => {
    const W = window.innerWidth;
    const out: string[] = [];
    for (const el of document.querySelectorAll('body *')) {
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.right <= W + 0.5) continue;
      const pr = el.parentElement?.getBoundingClientRect();
      if (pr && pr.right > W + 0.5) continue;
      // Content inside its own scrolling strip does not make the page scroll.
      let scrolls = false;
      for (let a = el.parentElement; a && a !== document.body; a = a.parentElement) {
        if (getComputedStyle(a).overflowX !== 'visible') scrolls = true;
      }
      if (scrolls) continue;
      out.push(`${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ''}${[...el.classList].map((c) => `.${c}`).join('')} (right ${Math.round(r.right)}px)`);
    }
    return { px: document.documentElement.scrollWidth - W, culprits: out.slice(0, 8).join(', ') };
  });
}

/** Make every glyph wider, as with the fallback fonts on some Linux CI images. */
async function widenFonts(page: Page, spacing = '0.1em') {
  await page.evaluate((sp) => {
    const sheet = [...document.styleSheets].find((x) => x.href?.endsWith('/styles.css'));
    sheet?.insertRule(`* { letter-spacing: ${sp} !important; }`, sheet.cssRules.length);
  }, spacing);
}

async function inspect(page: Page, name: string) {
  const input = page.getByLabel('Public GitHub repository URL');
  await input.fill(DEMO(name));
  await input.press('Enter');
  await page.locator('#inspection').waitFor({ state: 'visible' });
}

test('main flow by keyboard: inspect, choose, confirm, run, read the result', async () => {
  runner.script = { lines: ['running tests\n', '<img src=x onerror="window.__xss=1">\n', 'ok 2 tests\n'], delayMs: 300 };
  const page = await open();
  assert.ok(await page.getByRole('heading', { name: 'From GitHub link to running project.' }).isVisible());
  assert.ok(await page.getByRole('heading', { name: 'Before anything runs' }).isVisible());

  await inspect(page, 'node-hello');
  // Focus moves to the results heading for screen-reader and keyboard users.
  assert.equal(await page.evaluate(() => document.activeElement?.id), 'inspection-title');
  assert.ok(await page.getByRole('link', { name: 'unbox-demo/node-hello' }).isVisible());
  assert.match(await page.locator('.commit-tag code').innerText(), /^[a-f0-9]{40}$/);

  await page.getByRole('radio', { name: /npm test/ }).focus();
  await page.keyboard.press('Space');
  const plan = page.locator('#confirm-plan');
  await plan.waitFor();
  assert.match(await plan.innerText(), /npm test/);
  assert.match(await plan.innerText(), /Network: none/);
  assert.match(await plan.innerText(), /node --test/, 'shows the repository-defined script it will run');

  const start = page.getByRole('button', { name: 'Start check' });
  assert.equal(await start.isDisabled(), true, 'disabled until confirmed');
  await page.getByLabel(/I understand that code from unbox-demo\/node-hello/).check();
  assert.equal(await start.isDisabled(), false);
  await start.press('Enter');

  await page.getByText('Check passed', { exact: true }).first().waitFor({ timeout: 10_000 });
  const log = page.locator('#log');
  assert.match(await log.innerText(), /<img src=x onerror/);
  assert.equal(await log.locator('img').count(), 0, 'log output is never rendered as HTML');
  assert.equal(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss), undefined);
  assert.match(await page.locator('#run-result').innerText(), /does not mean the code is safe/);
  assert.ok(await page.getByRole('button', { name: /unbox-demo\/node-hello/ }).isVisible(), 'appears in session history');
  assert.deepEqual((page as unknown as { __errors: string[] }).__errors, []);
  await page.close();
});

test('error and empty states', async () => {
  const page = await open();
  await page.getByRole('button', { name: 'Inspect' }).click();
  assert.match(await page.locator('#url-error').innerText(), /Enter a GitHub repository URL/);
  assert.equal(await page.getByLabel('Public GitHub repository URL').getAttribute('aria-invalid'), 'true');

  await page.getByLabel('Public GitHub repository URL').fill('https://gitlab.com/a/b');
  await page.getByRole('button', { name: 'Inspect' }).click();
  await page.locator('#url-error').getByText(/Only public repositories on github.com/).waitFor();

  await page.getByLabel('Public GitHub repository URL').fill(DEMO('missing-repo'));
  await page.getByRole('button', { name: 'Inspect' }).click();
  await page.locator('#url-error').getByText(/only serves the bundled repositories/).waitFor();

  await inspect(page, 'makefile-only');
  assert.ok(await page.getByRole('heading', { name: 'No supported checks for this repository' }).isVisible());
  assert.match(await page.locator('#detection').innerText(), /never runs Makefiles/);
  await page.close();
});

test('dependency installs need a second, explicit confirmation', async () => {
  const page = await open();
  await inspect(page, 'node-with-deps');
  await page.getByRole('radio', { name: /npm test/ }).check();
  assert.match(await page.locator('#confirm-plan').innerText(), /--ignore-scripts/);
  assert.match(await page.locator('#confirm-plan').innerText(), /public package registry only/);
  await page.getByLabel(/I understand that code from/).check();
  const start = page.getByRole('button', { name: 'Start check' });
  assert.equal(await start.isDisabled(), true);
  await page.getByLabel(/downloads dependencies from public package registries/).check();
  assert.equal(await start.isDisabled(), false);
  await page.close();
});

test('cancel stops a running check and the UI reports it truthfully', async () => {
  runner.script = { lines: ['long test…\n'], hang: true };
  const page = await open();
  await inspect(page, 'go-hello');
  await page.getByRole('radio', { name: /go test/ }).check();
  await page.getByLabel(/I understand that code from/).check();
  await page.getByRole('button', { name: 'Start check' }).click();
  await page.locator('#chamber[data-active="true"]').waitFor();
  await page.getByRole('button', { name: 'Cancel run' }).click();
  await page.locator('#run-result').getByText(/every process in it were removed/).waitFor({ timeout: 10_000 });
  runner.script = { lines: ['ok\n'] };
  await page.close();
});

test('execution disabled: everything is reviewable but nothing can start', async () => {
  const off = new FakeRunner();
  off.statusOverride = { available: false, isolation: 'none', label: 'Execution disabled', reason: 'Execution is disabled on this deployment.' };
  const s = await startServer({ runner: off });
  try {
    const page = await open(s.base);
    assert.match(await page.locator('#exec-status').innerText(), /Execution disabled/);
    await inspect(page, 'python-hello');
    assert.ok(await page.getByRole('heading', { name: 'Execution is unavailable on this deployment' }).isVisible());
    await page.getByRole('radio', { name: /unittest/ }).check();
    await page.getByLabel(/I understand that code from/).check();
    assert.equal(await page.getByRole('button', { name: 'Start check' }).isDisabled(), true);
    assert.match(await page.locator('#start-help').innerText(), /disabled/);
    await page.close();
  } finally {
    await s.close();
  }
});

test('mobile layout has no horizontal scrolling; reduced motion stops the hazard band', async () => {
  runner.script = { lines: ['x\n'], hang: true };
  const page = await open(srv.base, { viewport: { width: 375, height: 800 }, reducedMotion: 'reduce' });
  await inspect(page, 'rust-hello');
  await page.getByRole('radio', { name: /cargo test/ }).check();
  await page.getByLabel(/I understand that code from/).check();
  await page.getByRole('button', { name: 'Start check' }).click();
  await page.locator('#chamber[data-active="true"]').waitFor();
  const overflow = await horizontalOverflow(page);
  assert.ok(overflow.px <= 0, `horizontal overflow ${overflow.px}px: ${overflow.culprits}`);
  const anim = await page.locator('.chamber-band').evaluate((el) => getComputedStyle(el).animationName);
  assert.equal(anim, 'none');
  await page.getByRole('button', { name: 'Cancel run' }).click();
  await page.locator('#run-result').waitFor();
  runner.script = { lines: ['ok\n'] };
  await page.close();
});

test('every interactive control has an accessible name and visible focus', async () => {
  const page = await open();
  await inspect(page, 'node-hello');
  await page.getByRole('radio', { name: /npm test/ }).check();
  const unnamed = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of document.querySelectorAll('button, input, a[href], [tabindex="0"]')) {
      const e = el as HTMLElement;
      if (e.offsetParent === null) continue;
      const labelled =
        e.getAttribute('aria-label') ||
        e.getAttribute('aria-labelledby') ||
        (e instanceof HTMLInputElement && e.labels && e.labels.length > 0) ||
        (e.textContent ?? '').trim();
      if (!labelled) out.push(e.outerHTML.slice(0, 80));
    }
    return out;
  });
  assert.deepEqual(unnamed, []);
  await page.keyboard.press('Tab');
  const outline = await page.evaluate(() => getComputedStyle(document.activeElement as Element).outlineStyle);
  assert.notEqual(outline, 'none');
  await page.close();
});

test('hidden elements stay hidden (no CSS display rule overrides [hidden])', async () => {
  const page = await open();
  assert.equal(await page.locator('#inspect-loading').isVisible(), false);
  await inspect(page, 'node-hello');
  await page.getByRole('radio', { name: /npm test/ }).check();
  assert.equal(await page.locator('#ack-install-row').isVisible(), false, 'no dependency confirmation for a check without dependencies');
  await page.getByLabel(/I understand that code from/).check();
  await page.getByRole('button', { name: 'Start check' }).click();
  await page.locator('#run-result').waitFor();
  assert.equal(await page.getByRole('button', { name: 'Cancel run' }).isVisible(), false, 'no cancel button after the run ended');
  await page.close();
});

test('investigation workspace: overview, findings with filters, setup steps and report downloads', async () => {
  const page = await open();
  await inspect(page, 'risky-node-api');
  assert.match(await page.locator('#overview').innerText(), /Node\.js server application/);
  assert.match(await page.locator('#overview').innerText(), /Express/);
  const summary = await page.locator('#security-summary').innerText();
  assert.match(summary, /1\s*Critical/i);
  await page.getByRole('button', { name: /^Critical \(1\)$/ }).click();
  assert.equal(await page.locator('#findings .finding').count(), 1);
  await page.locator('#findings .finding summary').first().click();
  assert.match(await page.locator('#findings .finding').first().innerText(), /Risk:[\s\S]*Recommendation:/);
  await page.getByRole('button', { name: /^All \(/ }).click();
  assert.ok((await page.locator('#findings .finding').count()) >= 5);
  await page.getByLabel('Filter by status').selectOption('confirmed');
  for (const t of await page.locator('#findings .finding').allInnerTexts()) assert.ok(t.length > 0);
  assert.match(await page.locator('#setup').innerText(), /npm install --ignore-scripts/);
  assert.match(await page.locator('#setup').innerText(), /run code from this repository/);
  assert.match(await page.locator('#preview').innerText(), /No live preview/);
  const md = page.getByRole('link', { name: 'Download Markdown report' });
  assert.match((await md.getAttribute('href')) ?? '', /^\/api\/inspections\/[a-f0-9]{32}\/report\?format=md$/);
  const download = await Promise.all([page.waitForEvent('download'), md.click()]);
  assert.match(download[0].suggestedFilename(), /^unboxanyrepo-unbox-demo-risky-node-api-[a-f0-9]{7}\.md$/);
  assert.deepEqual((page as unknown as { __errors: string[] }).__errors, []);
  await page.close();
});

test('static preview runs inside the dashboard, isolated from the app', async () => {
  const page = await open();
  await inspect(page, 'static-site');
  await page.getByRole('button', { name: 'Start preview' }).click();
  const frame = page.frameLocator('.preview-frame');
  await frame.locator('#result').waitFor({ timeout: 10_000 });
  assert.match(await frame.locator('#result').innerText(), /Tip: 6\.00/);
  assert.equal(await frame.locator('img').evaluate((i) => (i as HTMLImageElement).naturalWidth > 0), true, 'absolute-path assets load');
  assert.equal(await frame.locator('body').evaluate(() => { try { void document.cookie; return 'readable'; } catch { return 'blocked'; } }), 'blocked');
  await page.getByRole('button', { name: 'Stop' }).click();
  await page.getByText('The preview is not running.').waitFor();
  assert.ok(await page.getByRole('button', { name: 'Restart preview' }).isVisible());
  await page.close();
});

test('mobile: the investigation workspace has no horizontal scrolling', async () => {
  const page = await open(srv.base, { viewport: { width: 375, height: 800 } });
  await inspect(page, 'flask-app');
  await page.locator('#sec-setup').scrollIntoViewIfNeeded();
  const overflow = await horizontalOverflow(page);
  assert.ok(overflow.px <= 0, `horizontal overflow ${overflow.px}px: ${overflow.culprits}`);
  await page.close();
});

test('mobile: no horizontal scrolling even with wider fonts', async () => {
  for (const name of ['flask-app', 'risky-node-api']) {
    const page = await open(srv.base, { viewport: { width: 375, height: 800 } });
    await widenFonts(page);
    await inspect(page, name);
    const overflow = await horizontalOverflow(page);
    assert.ok(overflow.px <= 0, `${name}: horizontal overflow ${overflow.px}px: ${overflow.culprits}`);
    await page.close();
  }
});
