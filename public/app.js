// @ts-check
/**
 * RepoRadar client. Plain DOM, no framework.
 * Every piece of text that originates from a repository, GitHub or the sandbox
 * is inserted with textContent / createTextNode. innerHTML is never used.
 */

/** @typedef {{ kind: string, title: string, argv: string[], network: string, env?: Record<string,string> }} Step */
/** @typedef {{ source: string, text: string }} RepoScript */
/** @typedef {{ id: string, ecosystem: string, title: string, summary: string, executes: string, repoScripts: RepoScript[], notes: string[], installsDependencies: boolean, steps: Step[], detected: boolean, runnable: boolean, blockedReason?: string }} Check */
/** @typedef {{ available: boolean, isolation: string, label: string, reason?: string, dependencyFetch: boolean, dependencyFetchReason?: string, limits?: { cpus: number, memoryMiB: number, pids: number, workspaceMiB: number, installTimeoutSec: number, checkTimeoutSec: number } }} Runner */
/** @typedef {{ id: string, demo: boolean, notice?: string, repo: { fullName: string, owner: string, name: string, description: string|null, defaultBranch: string, language: string|null, htmlUrl: string, archived: boolean, fork: boolean }, commit: { sha: string, source: string }, source: { fileCount: number, totalBytes: number, skippedSymlinkCount: number, skippedSymlinks: string[] }, detection: { status: string, ecosystems: { ecosystem: string, label: string, confidence: string, evidence: string[], notes: string[] }[], warnings: string[], unsupportedSignals: string[] }, checks: Check[], runner: Runner }} Inspection */
/** @typedef {{ seq: number, kind: string, text: string }} LogLine */
/** @typedef {{ id: string, state: string, terminal: boolean, repo: { fullName: string, htmlUrl: string }, commitSha: string, demo: boolean, check: { id: string, title: string, ecosystem: string, installsDependencies: boolean }, steps: Step[], createdAt: string, startedAt?: string, finishedAt?: string, durationMs?: number, queuePosition?: number, exitCode?: number, failedStep?: string, message?: string, cleanup?: string, isolation: string, runnerLabel: string, cancelRequested: boolean, log: { truncated: boolean, receivedBytes: number }, nextSteps: string[] }} Run */

/** @type {{ config: any, inspection: Inspection|null, selected: Check|null, run: Run|null, lastSeq: number, source: EventSource|null, poll: number|null, timer: number|null, history: Run[] }} */
const state = { config: null, inspection: null, selected: null, run: null, lastSeq: 0, source: null, poll: null, timer: null, history: [] };

/** @param {string} id */
function $(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el;
}

/**
 * Create an element. Children may be nodes or strings (inserted as text).
 * @param {string} tag
 * @param {Record<string, string|boolean|undefined>} [attrs]
 * @param {(Node|string|null|undefined|false)[]} [children]
 */
function h(tag, attrs = {}, children = []) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k === 'class') el.className = String(v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    el.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return el;
}

/**
 * Replace an element's children, skipping null/undefined/false entries.
 * @param {Element} el
 * @param {(Node|string|null|undefined|false)[]} kids
 */
function fill(el, ...kids) {
  el.replaceChildren(.../** @type {(Node|string)[]} */ (kids.filter((k) => k !== null && k !== undefined && k !== false)));
}

/** @param {number} n */
function bytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

/** @param {number} ms */
function duration(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m ${String(s % 60).padStart(2, '0')}s` : `${s}s`;
}

const STATE_LABEL = /** @type {Record<string,string>} */ ({
  queued: 'Queued',
  preparing: 'Preparing sandbox',
  installing: 'Installing dependencies',
  running: 'Running check',
  succeeded: 'Check passed',
  failed: 'Check failed',
  timed_out: 'Timed out',
  cancelled: 'Cancelled',
  unavailable: 'Could not run',
});

class ApiError extends Error {
  /** @param {number} status @param {string} code @param {string} message @param {number|undefined} retryAfter */
  constructor(status, code, message, retryAfter) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

/**
 * @param {string} path
 * @param {{ method?: string, body?: unknown }} [opts]
 */
async function api(path, opts = {}) {
  /** @type {RequestInit} */
  const init = { method: opts.method ?? 'GET', credentials: 'same-origin', headers: {} };
  if (opts.body !== undefined) {
    init.headers = { 'Content-Type': 'application/json' };
    init.body = JSON.stringify(opts.body);
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiError(0, 'network', 'Could not reach the server. Check your connection and try again.', undefined);
  }
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* non-JSON */
  }
  if (!res.ok) {
    const e = data && data.error ? data.error : { code: 'http_error', message: `Request failed (${res.status}).` };
    throw new ApiError(res.status, e.code, e.message, e.retryAfterSec);
  }
  return data;
}

// ------------------------------------------------------------------ config

async function loadConfig() {
  try {
    state.config = await api('/api/config');
  } catch (err) {
    setExecStatus('none', 'Server unreachable');
    return;
  }
  const cfg = state.config;
  for (const el of document.querySelectorAll('[data-product-name]')) el.textContent = cfg.productName;
  const r = /** @type {Runner} */ (cfg.runner);
  if (r.available) setExecStatus(r.isolation, r.isolation === 'unsafe-local' ? 'Unsafe local runner' : `Sandbox ready: ${r.label}`);
  else setExecStatus('none', 'Execution disabled');
  $('exec-status').title = r.available ? r.label : r.reason ?? '';

  const banner = $('mode-banner');
  if (r.isolation === 'unsafe-local' && r.available) {
    banner.dataset.kind = 'unsafe';
    banner.textContent = 'Unsafe local development mode: checks run in plain containers (runc), which are not a strong sandbox. Do not expose this instance to anyone else.';
    banner.hidden = false;
  } else if (cfg.demo) {
    banner.dataset.kind = 'demo';
    banner.textContent = 'Demo mode: GitHub is not contacted. Pick one of the bundled demo repositories below; their “commits” are content hashes of the fixtures.';
    banner.hidden = false;
  }

  const examples = $('examples');
  for (const ex of cfg.examples ?? []) {
    const b = h('button', { type: 'button', class: 'example', title: ex.description ?? ex.url }, [ex.label]);
    b.addEventListener('click', () => {
      const input = /** @type {HTMLInputElement} */ ($('repo-url'));
      input.value = ex.url;
      input.focus();
    });
    examples.append(b);
  }
  examples.hidden = (cfg.examples ?? []).length === 0;
  $('supported-list').textContent = cfg.supported.map((/** @type {any} */ s) => `${s.label} (${s.checks.join(', ')})`).join('; ');
}

/** @param {string} kind @param {string} text */
function setExecStatus(kind, text) {
  const el = $('exec-status');
  el.dataset.state = kind;
  $('exec-status-text').textContent = text;
}

// ------------------------------------------------------------------ inspect

async function onInspect(/** @type {SubmitEvent} */ ev) {
  ev.preventDefault();
  const input = /** @type {HTMLInputElement} */ ($('repo-url'));
  const btn = /** @type {HTMLButtonElement} */ ($('inspect-btn'));
  const err = $('url-error');
  err.hidden = true;
  input.removeAttribute('aria-invalid');
  const url = input.value.trim();
  if (url === '') {
    showFieldError(err, 'Enter a GitHub repository URL.', 'Example: https://github.com/owner/repo');
    input.setAttribute('aria-invalid', 'true');
    input.focus();
    return;
  }
  btn.disabled = true;
  btn.textContent = 'Inspecting…';
  $('inspect-loading').hidden = false;
  $('inspection').hidden = true;
  try {
    const insp = /** @type {Inspection} */ (await api('/api/inspect', { method: 'POST', body: { url } }));
    state.inspection = insp;
    state.selected = null;
    renderInspection(insp);
    $('inspection').hidden = false;
    $('inspection-title').focus();
  } catch (e) {
    const ae = /** @type {ApiError} */ (e);
    showFieldError(err, ae.message, hintFor(ae));
    input.setAttribute('aria-invalid', 'true');
    input.focus();
  } finally {
    btn.disabled = false;
    btn.textContent = 'Inspect';
    $('inspect-loading').hidden = true;
  }
}

/** @param {ApiError} e */
function hintFor(e) {
  if (e.code === 'rate_limited' || e.code === 'github_rate_limited') {
    return e.retryAfter ? `You can try again in about ${duration(e.retryAfter * 1000)}.` : 'Wait a little and try again.';
  }
  if (e.code === 'github_not_found') return 'Check the spelling. Private repositories are not supported.';
  if (e.code === 'source_too_large') return 'Very large repositories are not supported in this version.';
  if (e.code === 'unsafe_source') return 'The archive contained entries that are not allowed (for example links pointing outside the repository).';
  if (e.code === 'invalid_url') return 'Example: https://github.com/owner/repo';
  return '';
}

/** @param {HTMLElement} el @param {string} msg @param {string} hint */
function showFieldError(el, msg, hint) {
  fill(el, msg, hint ? h('span', { class: 'hint' }, [hint]) : null);
  el.hidden = false;
}

/** @param {Inspection} insp */
function renderInspection(insp) {
  const r = insp.repo;
  const facts = [
    ['Default branch', r.defaultBranch],
    ['Primary language', r.language ?? 'Not reported'],
    ['Files', `${insp.source.fileCount.toLocaleString()} (${bytes(insp.source.totalBytes)})`],
  ];
  if (insp.source.skippedSymlinkCount > 0) facts.push(['Symlinks skipped', String(insp.source.skippedSymlinkCount)]);
  const flags = [r.archived ? 'archived' : '', r.fork ? 'fork' : ''].filter(Boolean);

  fill($('repo-card'),
    h('div', { class: 'repo-title' }, [
      h('a', { href: r.htmlUrl, rel: 'noopener noreferrer', target: '_blank' }, [r.fullName]),
      flags.length ? h('span', { class: 'tag' }, [flags.join(', ')]) : null,
      insp.demo ? h('span', { class: 'tag' }, ['demo fixture']) : null,
    ]),
    h('p', { class: 'repo-desc' }, [r.description ?? 'No description.']),
    h('dl', { class: 'facts' }, facts.map(([k, v]) => h('div', {}, [h('dt', {}, [k]), h('dd', {}, [v])]))),
    h('div', { class: 'commit-tag' }, [
      h('span', { class: 'label' }, [insp.commit.source === 'url' ? 'Pinned commit (from URL)' : `Pinned commit (head of ${r.defaultBranch})`]),
      h('code', {}, [insp.commit.sha]),
      copyButton(insp.commit.sha, 'Copy SHA'),
    ]),
    insp.notice ? h('p', { class: 'notice' }, [insp.notice]) : null,
  );

  renderDetection(insp);
  renderChecks(insp);
  $('confirm-box').hidden = true;
}

/** @param {string} text @param {string} label */
function copyButton(text, label) {
  const b = h('button', { type: 'button', class: 'btn btn-quiet btn-small' }, [label]);
  b.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(text);
      b.textContent = 'Copied';
    } catch {
      b.textContent = 'Copy failed';
    }
    setTimeout(() => (b.textContent = label), 1500);
  });
  return b;
}

/** @param {Inspection} insp */
function renderDetection(insp) {
  const d = insp.detection;
  const box = $('detection');
  if (d.status === 'unsupported') {
    const others = d.unsupportedSignals.length ? `Found: ${d.unsupportedSignals.join(', ')}.` : 'No supported project files were found at the repository root.';
    fill(box,
      h('div', { class: 'empty-state' }, [
        h('h3', {}, ['No supported checks for this repository']),
        h('p', {}, [others]),
        h('p', {}, [`This version detects Node.js (npm), Python, Go modules and Rust (Cargo) projects at the repository root, and never runs Makefiles, Dockerfiles, CI workflows or scripts from README files.`]),
        ...d.warnings.map((w) => h('p', {}, [w])),
      ]),
    );
    $('checks-fieldset').hidden = true;
    return;
  }
  $('checks-fieldset').hidden = false;
  fill(box,
    h(
      'ul',
      { class: 'eco-list', 'aria-label': 'Detected ecosystems' },
      d.ecosystems.map((e) => h('li', { class: 'eco' }, [e.label, h('span', { class: 'conf' }, [`${e.confidence} confidence, from ${e.evidence.join(', ')}`])])),
    ),
    ...d.ecosystems.filter((e) => e.notes.length).map((e) => h('ul', { class: 'eco-notes' }, e.notes.map((n) => h('li', {}, [n])))),
    d.warnings.length ? h('ul', { class: 'warn-list' }, d.warnings.map((w) => h('li', {}, [w]))) : null,
    d.status === 'no_supported_checks'
      ? h('div', { class: 'empty-state' }, [
          h('h3', {}, ['Could not determine a check to run']),
          h('p', {}, ['The project was recognised, but none of the predefined checks apply with enough confidence. Reasons are listed under each check below.']),
        ])
      : null,
    !insp.runner.available
      ? h('div', { class: 'empty-state' }, [
          h('h3', {}, ['Execution is unavailable on this deployment']),
          h('p', {}, [insp.runner.reason ?? 'No sandbox is configured.']),
          h('p', {}, ['You can still review exactly what each check would do.']),
        ])
      : null,
  );
}

/** @param {Inspection} insp */
function renderChecks(insp) {
  const list = $('checks-list');
  list.replaceChildren();
  for (const c of insp.checks) {
    const id = `check-${c.id.replace(/[^a-z0-9-]/g, '-')}`;
    const input = h('input', { type: 'radio', name: 'check', id, value: c.id, 'aria-describedby': `${id}-desc` });
    const tags = [];
    tags.push(h('span', { class: 'tag' }, [c.ecosystem]));
    if (c.installsDependencies) tags.push(h('span', { class: 'tag tag-amber' }, ['downloads dependencies']));
    const label = h('label', { class: 'check', for: id, 'data-disabled': c.runnable ? 'false' : 'true' }, [
      input,
      h('span', {}, [h('span', { class: 'check-title' }, [c.title]), h('span', { class: 'check-tags' }, tags)]),
      h('div', { class: 'check-body', id: `${id}-desc` }, [
        h('p', {}, [c.summary]),
        c.blockedReason ? h('p', { class: 'blocked' }, [`Unavailable: ${c.blockedReason}`]) : null,
      ]),
    ]);
    input.addEventListener('change', () => selectCheck(c));
    list.append(label);
  }
}

/** @param {Check} c */
function selectCheck(c) {
  state.selected = c;
  const insp = /** @type {Inspection} */ (state.inspection);
  const plan = $('confirm-plan');
  const steps = c.steps.map((s) =>
    h('li', {}, [
      h('span', { class: 'step-title' }, [`${s.kind === 'install' ? 'Install' : 'Check'}: ${s.title}`]),
      h('code', { class: 'cmd' }, [s.argv.join(' ')]),
      h('span', { class: `net ${s.network === 'none' ? 'net-none' : 'net-proxy'}` }, [
        s.network === 'none' ? 'Network: none' : 'Network: public package registry only, through the egress proxy',
      ]),
      s.env && Object.keys(s.env).length
        ? h('details', {}, [h('summary', {}, ['Environment variables set by the template']), h('code', { class: 'cmd' }, [Object.entries(s.env).map(([k, v]) => `${k}=${v}`).join('\n')])])
        : null,
    ]),
  );
  plan.replaceChildren(
    h('p', {}, [`Planned steps for ${c.title}, at commit ${insp.commit.sha.slice(0, 12)}:`]),
    h('ol', {}, steps),
    h('div', { class: 'executes' }, [
      h('p', {}, [c.executes]),
      ...c.repoScripts.map((s) => h('p', {}, [`${s.source}: `, h('span', { class: 'script-text' }, [s.text])])),
      ...c.notes.map((n) => h('p', { class: 'help-inline' }, [n])),
    ]),
  );
  $('ack-code-text').textContent = `I understand that code from ${insp.repo.fullName} at ${insp.commit.sha.slice(0, 12)} will run inside the sandbox.`;
  const installRow = $('ack-install-row');
  installRow.hidden = !c.installsDependencies;
  $('ack-install-text').textContent =
    'I understand this check downloads dependencies from public package registries first. Install scripts are disabled, but downloaded packages are also untrusted code.';
  /** @type {HTMLInputElement} */ ($('ack-code')).checked = false;
  /** @type {HTMLInputElement} */ ($('ack-install')).checked = false;
  $('run-error').hidden = true;
  $('confirm-box').hidden = false;
  updateStartButton();
}

function updateStartButton() {
  const c = state.selected;
  const btn = /** @type {HTMLButtonElement} */ ($('start-btn'));
  const help = $('start-help');
  const ack = /** @type {HTMLInputElement} */ ($('ack-code')).checked;
  const ackInstall = /** @type {HTMLInputElement} */ ($('ack-install')).checked;
  const busy = state.run !== null && !state.run.terminal;
  let reason = '';
  if (!c) reason = 'Choose a check first.';
  else if (!c.runnable) reason = c.blockedReason ?? 'This check is unavailable.';
  else if (busy) reason = 'Wait for the current run to finish.';
  else if (!ack || (c.installsDependencies && !ackInstall)) reason = 'Tick the confirmation to enable.';
  btn.disabled = reason !== '';
  help.textContent = reason || 'Runs once. You can cancel while it runs.';
}

async function onStart(/** @type {SubmitEvent} */ ev) {
  ev.preventDefault();
  const c = state.selected;
  const insp = state.inspection;
  if (!c || !insp) return;
  const btn = /** @type {HTMLButtonElement} */ ($('start-btn'));
  btn.disabled = true;
  $('run-error').hidden = true;
  try {
    const { run } = await api('/api/runs', { method: 'POST', body: { inspectionId: insp.id, checkId: c.id, acknowledged: true } });
    showRun(run, []);
    follow(run);
    await refreshHistory();
    $('run-title').focus();
  } catch (e) {
    const ae = /** @type {ApiError} */ (e);
    showFieldError($('run-error'), ae.message, ae.code === 'inspection_expired' ? 'Inspect the repository again to continue.' : hintFor(ae));
  } finally {
    updateStartButton();
  }
}

// ------------------------------------------------------------------ run view

/** @param {Run} run @param {LogLine[]} lines */
function showRun(run, lines) {
  stopFollowing();
  state.run = run;
  state.lastSeq = 0;
  $('log').replaceChildren();
  $('run').hidden = false;
  /** @type {HTMLAnchorElement} */ ($('download-log')).href = `/api/runs/${run.id}/log`;
  appendLines(lines);
  renderRun(run);
}

/** @param {LogLine[]} lines */
function appendLines(lines) {
  if (!lines.length) return;
  const log = $('log');
  const nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
  const frag = document.createDocumentFragment();
  for (const l of lines) {
    if (l.seq > 0 && l.seq <= state.lastSeq) continue;
    if (l.kind === 'system') frag.append(h('span', { class: l.seq === 0 ? 'gap' : 'sys' }, [`# ${l.text}`]), '\n');
    else frag.append(document.createTextNode(`${l.text}\n`));
    if (l.seq > state.lastSeq) state.lastSeq = l.seq;
  }
  log.append(frag);
  if (nearBottom) log.scrollTop = log.scrollHeight;
}

/** @param {Run} run */
function renderRun(run) {
  // Responses can arrive out of order (e.g. a cancel response after the stream's final event).
  // A finished run never goes back to a running state.
  if (state.run && state.run.id === run.id && state.run.terminal && !run.terminal) return;
  state.run = run;
  const chamber = $('chamber');
  const active = !run.terminal && run.state !== 'queued';
  chamber.dataset.active = String(active);
  chamber.dataset.outcome = run.terminal ? run.state : '';
  let label = STATE_LABEL[run.state] ?? run.state;
  if (run.state === 'queued' && run.queuePosition) label = `Queued (position ${run.queuePosition})`;
  if (run.cancelRequested && !run.terminal) label = 'Cancelling…';
  $('run-state').textContent = label;
  $('run-meta').textContent = `${run.check.title} on ${run.repo.fullName} at ${run.commitSha.slice(0, 12)}, in ${run.runnerLabel}`;

  const phases = [{ key: 'queued', label: 'Queued' }, { key: 'preparing', label: 'Prepare sandbox' }];
  if (run.check.installsDependencies) phases.push({ key: 'installing', label: 'Install dependencies' });
  phases.push({ key: 'running', label: 'Run check' }, { key: 'done', label: 'Result' });
  const order = phases.map((p) => p.key);
  const current = run.terminal ? 'done' : run.state;
  const ci = order.indexOf(current);
  $('phases').replaceChildren(
    ...phases.map((p, i) => h('li', { 'data-status': i < ci ? 'done' : i === ci ? 'current' : 'todo', 'aria-current': i === ci ? 'step' : undefined }, [p.label])),
  );

  const cancel = /** @type {HTMLButtonElement} */ ($('cancel-btn'));
  cancel.hidden = run.terminal;
  cancel.disabled = run.cancelRequested;

  const note = [];
  if (run.log.truncated) note.push(run.terminal ? 'Long output: the middle was omitted.' : 'Output limit reached; the end of the log will appear when the run finishes.');
  if (!run.terminal && run.log.receivedBytes) note.push(`${bytes(run.log.receivedBytes)} received`);
  $('log-note').textContent = note.join(' ');

  const result = $('run-result');
  if (run.terminal) {
    result.dataset.outcome = run.state;
    const dl = [['Outcome', STATE_LABEL[run.state] ?? run.state]];
    if (run.exitCode !== undefined) dl.push(['Exit code', String(run.exitCode)]);
    if (run.durationMs !== undefined) dl.push(['Duration', duration(run.durationMs)]);
    dl.push(['Commit', run.commitSha.slice(0, 12)]);
    if (run.cleanup === 'confirmed') dl.push(['Sandbox', 'removed']);
    else if (run.cleanup === 'unconfirmed') dl.push(['Sandbox', 'removal not confirmed']);
    fill(result,
      h('h3', {}, [STATE_LABEL[run.state] ?? run.state]),
      run.message ? h('p', {}, [run.message]) : null,
      h('dl', {}, dl.map(([k, v]) => h('div', {}, [h('dt', {}, [k]), h('dd', {}, [v])]))),
      run.nextSteps.length ? h('ul', {}, run.nextSteps.map((s) => h('li', {}, [s]))) : null,
    );
    result.hidden = false;
  } else {
    result.hidden = true;
  }
  tickElapsed();
  if (!run.terminal && state.timer === null) state.timer = window.setInterval(tickElapsed, 1000);
  if (run.terminal && state.timer !== null) {
    clearInterval(state.timer);
    state.timer = null;
  }
  updateStartButton();
  markHistory();
}

function tickElapsed() {
  const run = state.run;
  const el = $('run-elapsed');
  if (!run || !run.startedAt) {
    el.textContent = '';
    return;
  }
  const end = run.finishedAt ? Date.parse(run.finishedAt) : Date.now();
  el.textContent = duration(end - Date.parse(run.startedAt));
}

/** @param {Run} run */
function follow(run) {
  if (run.terminal) return;
  stopFollowing();
  const es = new EventSource(`/api/runs/${run.id}/events?after=${state.lastSeq}`);
  state.source = es;
  es.addEventListener('state', (e) => {
    const d = JSON.parse(/** @type {MessageEvent} */ (e).data);
    renderRun(d.run);
  });
  es.addEventListener('log', (e) => {
    const d = JSON.parse(/** @type {MessageEvent} */ (e).data);
    if (d.final) {
      // Final retained log (head + omitted marker + tail) replaces the live view.
      $('log').replaceChildren();
      state.lastSeq = 0;
    }
    appendLines(d.lines);
  });
  es.addEventListener('end', (e) => {
    const d = JSON.parse(/** @type {MessageEvent} */ (e).data);
    renderRun(d.run);
    stopFollowing();
    void refreshHistory();
  });
  es.addEventListener('error', () => {
    // Fall back to polling if the stream drops before the run ends.
    if (state.run && !state.run.terminal && state.poll === null) {
      es.close();
      state.source = null;
      state.poll = window.setInterval(pollRun, 2000);
    }
  });
}

async function pollRun() {
  const run = state.run;
  if (!run) return;
  try {
    const d = await api(`/api/runs/${run.id}`);
    if (d.run.terminal) {
      $('log').replaceChildren();
      state.lastSeq = 0;
      appendLines(d.lines);
      renderRun(d.run);
      stopFollowing();
      void refreshHistory();
    } else {
      appendLines(d.lines);
      renderRun(d.run);
    }
  } catch {
    /* keep polling */
  }
}

function stopFollowing() {
  state.source?.close();
  state.source = null;
  if (state.poll !== null) clearInterval(state.poll);
  state.poll = null;
}

async function onCancel() {
  const run = state.run;
  if (!run || run.terminal) return;
  const btn = /** @type {HTMLButtonElement} */ ($('cancel-btn'));
  btn.disabled = true;
  try {
    const d = await api(`/api/runs/${run.id}/cancel`, { method: 'POST', body: {} });
    renderRun(d.run);
  } catch (e) {
    $('copy-status').textContent = /** @type {Error} */ (e).message;
    btn.disabled = false;
  }
}

async function onCopyLog() {
  const run = state.run;
  if (!run) return;
  const status = $('copy-status');
  const btn = $('copy-log');
  try {
    const res = await fetch(`/api/runs/${run.id}/log`, { credentials: 'same-origin' });
    if (!res.ok) throw new Error('unavailable');
    await navigator.clipboard.writeText(await res.text());
    btn.textContent = 'Copied';
    status.textContent = 'Log copied to clipboard.';
  } catch {
    btn.textContent = 'Copy failed';
    status.textContent = 'Could not copy the log. Use Download instead.';
  }
  setTimeout(() => (btn.textContent = 'Copy log'), 1500);
}

// ------------------------------------------------------------------ history

async function refreshHistory() {
  try {
    const d = await api('/api/runs');
    state.history = d.runs;
  } catch {
    return;
  }
  renderHistory();
}

function renderHistory() {
  const list = $('history-list');
  $('history-empty').hidden = state.history.length > 0;
  list.replaceChildren(
    ...state.history.map((r) => {
      const b = h('button', { type: 'button', class: 'history-item', 'data-run': r.id }, [
        h('span', { class: 'h-repo' }, [r.repo.fullName]),
        h('span', { class: 'h-meta' }, [`${r.check.title} at ${r.commitSha.slice(0, 7)}`]),
        h('span', { class: 'badge', 'data-state': r.state, 'data-active': String(!r.terminal) }, [
          `${STATE_LABEL[r.state] ?? r.state}${r.durationMs !== undefined ? `, ${duration(r.durationMs)}` : ''}`,
        ]),
      ]);
      b.addEventListener('click', () => void openRun(r.id));
      return h('li', {}, [b]);
    }),
  );
  markHistory();
}

function markHistory() {
  for (const b of document.querySelectorAll('.history-item')) {
    const el = /** @type {HTMLElement} */ (b);
    el.setAttribute('aria-current', String(state.run !== null && el.dataset.run === state.run.id));
  }
}

/** @param {string} id */
async function openRun(id) {
  try {
    const d = await api(`/api/runs/${id}`);
    showRun(d.run, d.lines);
    follow(d.run);
    $('run-title').focus();
  } catch (e) {
    $('history-empty').hidden = false;
    $('history-empty').textContent = /** @type {Error} */ (e).message;
  }
}

// ------------------------------------------------------------------ boot

function boot() {
  $('inspect-form').addEventListener('submit', (e) => void onInspect(/** @type {SubmitEvent} */ (e)));
  $('run-form').addEventListener('submit', (e) => void onStart(/** @type {SubmitEvent} */ (e)));
  $('ack-code').addEventListener('change', updateStartButton);
  $('ack-install').addEventListener('change', updateStartButton);
  $('cancel-btn').addEventListener('click', () => void onCancel());
  $('copy-log').addEventListener('click', () => void onCopyLog());
  void loadConfig();
  void refreshHistory().then(() => {
    const active = state.history.find((r) => !r.terminal);
    if (active) void openRun(active.id);
  });
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();
