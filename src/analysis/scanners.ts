/**
 * Optional external scanners: Semgrep (syntax-aware rules) and Gitleaks
 * (secret detection). They are static analysers; they read files but never
 * execute repository code.
 *
 * Because they need files on disk, the already-sanitized text files are
 * written to a fresh private temporary directory (mode 0700, files 0600,
 * created exclusively, no symlinks), scanned, and the directory is always
 * removed. Scanners run with a minimal environment, a temporary HOME, metrics
 * and version checks off, and a hard timeout that kills the whole process
 * group. If a binary is missing the result says "not installed"; nothing
 * falls back silently.
 */
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AnalysisConfig, ScannerName } from '../config.ts';
import type { Finding, FindingCategory, Severity, ToolRun } from './types.ts';
import type { SourceView } from './source.ts';
import { make, excerpt } from './rules/finding.ts';
import { isPlainObject } from '../detect/util.ts';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const SEMGREP_RULES = path.join(ROOT, 'rules', 'semgrep', 'unboxanyrepo.yml');
const MAX_OUTPUT = 32 * 1024 * 1024;

interface ProcResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  spawnError: boolean;
}

function scannerEnv(home: string): Record<string, string> {
  return {
    PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
    HOME: home,
    XDG_CONFIG_HOME: path.join(home, '.config'),
    XDG_CACHE_HOME: path.join(home, '.cache'),
    LANG: 'C.UTF-8',
    SEMGREP_SEND_METRICS: 'off',
    SEMGREP_ENABLE_VERSION_CHECK: '0',
    NO_COLOR: '1',
  };
}

export function runProcess(bin: string, args: string[], opts: { timeoutMs: number; env: Record<string, string>; cwd?: string }): Promise<ProcResult> {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(bin, args, { shell: false, env: opts.env, cwd: opts.cwd ?? os.tmpdir(), stdio: ['ignore', 'pipe', 'pipe'], detached: true });
    } catch {
      resolve({ code: null, stdout: '', stderr: '', timedOut: false, spawnError: true });
      return;
    }
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let spawnError = false;
    child.stdout.on('data', (c: Buffer) => {
      if (stdout.length < MAX_OUTPUT) stdout += c.toString('utf8');
    });
    child.stderr.on('data', (c: Buffer) => {
      if (stderr.length < 64 * 1024) stderr += c.toString('utf8');
    });
    const killGroup = () => {
      try {
        if (child.pid) process.kill(-child.pid, 'SIGKILL');
      } catch {
        child.kill('SIGKILL');
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      killGroup();
    }, opts.timeoutMs);
    child.on('error', () => {
      spawnError = true;
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut, spawnError });
    });
  });
}

const versionCache = new Map<string, Promise<string | undefined>>();

/** Version string if the scanner binary runs, else undefined. Cached per binary. */
export function scannerVersion(name: ScannerName, bin: string): Promise<string | undefined> {
  const key = `${name}:${bin}`;
  let p = versionCache.get(key);
  if (!p) {
    const args = name === 'gitleaks' ? ['version'] : ['--version'];
    p = runProcess(bin, args, { timeoutMs: 20_000, env: scannerEnv(os.tmpdir()) }).then((r) => {
      if (r.spawnError || r.code !== 0) return undefined;
      const v = /\d+\.\d+\.\d+/.exec(r.stdout)?.[0];
      return v ?? (r.stdout.trim().slice(0, 40) || 'unknown');
    });
    versionCache.set(key, p);
  }
  return p;
}

/** Write sanitized text files into a new private directory. */
async function materialize(src: SourceView): Promise<{ dir: string; home: string }> {
  const base = await mkdtemp(path.join(os.tmpdir(), 'unbox-scan-'));
  const dir = path.join(base, 'src');
  const home = path.join(base, 'home');
  await mkdir(dir, { mode: 0o700 });
  await mkdir(home, { mode: 0o700 });
  for (const rel of src.textPaths()) {
    const text = src.text(rel);
    if (text === undefined) continue;
    const target = path.resolve(dir, rel);
    // Paths were validated by the archive sanitizer; check again before writing.
    if (!target.startsWith(dir + path.sep)) continue;
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await writeFile(target, text, { flag: 'wx', mode: 0o600 });
  }
  return { dir, home };
}

const SEMGREP_SEVERITY: Record<string, Severity> = { ERROR: 'high', WARNING: 'medium', INFO: 'low' };
const CATEGORIES: FindingCategory[] = ['secret', 'command-injection', 'code-execution', 'sql-injection', 'deserialization', 'path-traversal', 'install-script', 'docker', 'ci', 'network', 'auth', 'crypto', 'configuration'];

export function parseSemgrep(json: unknown, rootDir: string, lineText?: (file: string, line: number) => string | undefined): Finding[] {
  if (!isPlainObject(json) || !Array.isArray(json.results)) throw new Error('unexpected Semgrep output');
  const out: Finding[] = [];
  for (const r of json.results.slice(0, 500)) {
    if (!isPlainObject(r) || typeof r.check_id !== 'string' || typeof r.path !== 'string') continue;
    const extra = isPlainObject(r.extra) ? r.extra : {};
    const meta = isPlainObject(extra.metadata) ? extra.metadata : {};
    const rel = path.relative(rootDir, path.resolve(rootDir, r.path)).split(path.sep).join('/');
    if (rel.startsWith('..')) continue;
    const start = isPlainObject(r.start) && typeof r.start.line === 'number' ? r.start.line : undefined;
    const end = isPlainObject(r.end) && typeof r.end.line === 'number' ? r.end.line : start;
    const cat = typeof meta.category === 'string' && (CATEGORIES as string[]).includes(meta.category) ? (meta.category as FindingCategory) : 'other';
    const conf = typeof meta.confidence === 'string' ? meta.confidence.toLowerCase() : 'medium';
    const lines = typeof extra.lines === 'string' && !/requires login/i.test(extra.lines) ? extra.lines : start !== undefined ? (lineText?.(rel, start) ?? '') : '';
    const cwe = typeof meta.cwe === 'string' ? (/CWE-\d+/.exec(meta.cwe)?.[0] ?? undefined) : undefined;
    out.push(
      make('SG', {
        ruleId: `semgrep.${r.check_id.replace(/^.*?(uar\.)/, '$1').slice(0, 80)}`,
        title: excerpt(typeof extra.message === 'string' ? extra.message.split('.')[0] ?? r.check_id : r.check_id, 120),
        category: cat,
        severity: SEMGREP_SEVERITY[String(extra.severity)] ?? 'medium',
        confidence: conf === 'high' || conf === 'low' ? conf : 'medium',
        status: 'heuristic',
        file: rel,
        ...(start !== undefined ? { startLine: start } : {}),
        ...(end !== undefined ? { endLine: end } : {}),
        ...(lines ? { evidence: excerpt(lines) } : {}),
        risk: excerpt(typeof extra.message === 'string' ? extra.message : 'Matched a Semgrep rule.', 400),
        remediation: excerpt(typeof extra.message === 'string' && extra.message.includes('. ') ? extra.message.slice(extra.message.indexOf('. ') + 2) : 'Review the flagged code.', 300),
        method: 'semgrep',
        references: cwe ? [`https://cwe.mitre.org/data/definitions/${cwe.slice(4)}.html`] : [],
        ...(cwe ? { cwe } : {}),
      }),
    );
  }
  return out;
}

export function parseGitleaks(json: unknown, rootDir: string): Finding[] {
  if (!Array.isArray(json)) throw new Error('unexpected Gitleaks output');
  const out: Finding[] = [];
  for (const r of json.slice(0, 300)) {
    if (!isPlainObject(r) || typeof r.File !== 'string') continue;
    const rel = path.relative(rootDir, path.resolve(rootDir, r.File)).split(path.sep).join('/');
    if (rel.startsWith('..')) continue;
    const rule = typeof r.RuleID === 'string' ? r.RuleID.slice(0, 60) : 'secret';
    const start = typeof r.StartLine === 'number' ? r.StartLine : undefined;
    // generic-api-key is entropy-based and noisy; specific rules (aws, github, private keys...) are format-based.
    const generic = /^generic/.test(rule);
    const lowContext = /(^|\/)(tests?|__tests__|spec|fixtures?|examples?|samples?|docs?|testdata)\//i.test(rel);
    const severity: Severity = generic ? (lowContext ? 'low' : 'medium') : lowContext ? 'medium' : 'high';
    // Match/Secret are never copied, even though Gitleaks was asked to redact them.
    out.push(
      make('GL', {
        ruleId: `gitleaks.${rule}`,
        title: `Possible secret (${typeof r.Description === 'string' ? excerpt(r.Description, 80) : rule})`,
        category: 'secret',
        severity,
        confidence: generic ? 'low' : 'medium',
        status: generic ? 'heuristic' : 'unverified',
        file: rel,
        ...(start !== undefined ? { startLine: start, endLine: typeof r.EndLine === 'number' ? r.EndLine : start } : {}),
        evidence: `Gitleaks rule ${rule} matched at line ${start ?? '?'} (value redacted)`,
        risk: 'If this is a real credential it is exposed to anyone who can read the repository and its history.',
        remediation: 'Revoke and rotate the credential, remove it from the code and Git history, and load it from the environment or a secret manager.',
        method: 'gitleaks',
        references: ['https://github.com/gitleaks/gitleaks'],
        cwe: 'CWE-798',
      }),
    );
  }
  return out;
}

export interface ScannerOutcome {
  findings: Finding[];
  tools: ToolRun[];
}

let busy: Promise<unknown> = Promise.resolve();

/** Run the configured external scanners one inspection at a time. */
export function runScanners(src: SourceView, cfg: AnalysisConfig, timeoutMs: number): Promise<ScannerOutcome> {
  const next = busy.then(() => runScannersNow(src, cfg, timeoutMs));
  busy = next.catch(() => undefined);
  return next;
}

async function runScannersNow(src: SourceView, cfg: AnalysisConfig, timeoutMs: number): Promise<ScannerOutcome> {
  const wanted: ScannerName[] = cfg.scanners === 'off' ? [] : cfg.scanners === 'auto' ? ['semgrep', 'gitleaks'] : cfg.scanners;
  const tools: ToolRun[] = [];
  const findings: Finding[] = [];
  const available: { name: ScannerName; version: string }[] = [];
  for (const name of ['semgrep', 'gitleaks'] as const) {
    const label = name === 'semgrep' ? 'Semgrep' : 'Gitleaks';
    if (!wanted.includes(name)) {
      tools.push({ tool: label, state: 'disabled', message: 'Disabled by configuration (UNBOX_SCANNERS).', findings: 0 });
      continue;
    }
    const version = await scannerVersion(name, name === 'semgrep' ? cfg.semgrepBin : cfg.gitleaksBin);
    if (!version) {
      tools.push({ tool: label, state: 'not_installed', message: `${label} is not installed on this server, so its checks did not run.`, findings: 0 });
      continue;
    }
    available.push({ name, version });
  }
  if (available.length === 0 || src.textPaths().length === 0) {
    for (const a of available) tools.push({ tool: a.name === 'semgrep' ? 'Semgrep' : 'Gitleaks', state: 'skipped', version: a.version, message: 'No text files to scan.', findings: 0 });
    return { findings, tools };
  }

  let work: { dir: string; home: string } | undefined;
  try {
    work = await materialize(src);
    for (const a of available) {
      const started = Date.now();
      if (a.name === 'semgrep') {
        const r = await runProcess(
          cfg.semgrepBin,
          ['scan', '--config', SEMGREP_RULES, '--json', '--metrics=off', '--disable-version-check', '--no-git-ignore', '--timeout', '20', '--max-target-bytes', '1000000', '--jobs', '2', '--quiet', work.dir],
          { timeoutMs, env: scannerEnv(work.home), cwd: work.home },
        );
        tools.push(toolResult('Semgrep', a.version, r, started, () => {
          const f = parseSemgrep(JSON.parse(r.stdout), work!.dir, (file, line) => src.text(file)?.split(/\r?\n/)[line - 1]);
          findings.push(...f);
          return f.length;
        }, (code) => code === 0 || code === 1));
      } else {
        const report = path.join(work.home, 'gitleaks.json');
        const r = await runProcess(
          cfg.gitleaksBin,
          ['dir', work.dir, '--report-format', 'json', '--report-path', report, '--redact', '--no-banner', '--no-color', '--exit-code', '0', '--max-target-megabytes', '2', '--log-level', 'error'],
          { timeoutMs, env: scannerEnv(work.home), cwd: work.home },
        );
        let reportText = '';
        try {
          reportText = await readFile(report, 'utf8');
        } catch {
          reportText = '';
        }
        tools.push(toolResult('Gitleaks', a.version, { ...r, stdout: reportText }, started, () => {
          const f = parseGitleaks(JSON.parse(reportText || '[]'), work!.dir);
          findings.push(...f);
          return f.length;
        }, (code) => code === 0));
      }
    }
  } catch {
    tools.push({ tool: 'Scanners', state: 'failed', message: 'The scan workspace could not be prepared.', findings: 0 });
  } finally {
    if (work) await rm(path.dirname(work.dir), { recursive: true, force: true }).catch(() => {});
  }
  return { findings, tools };
}

function toolResult(tool: string, version: string, r: ProcResult, started: number, parse: () => number, okCode: (c: number | null) => boolean): ToolRun {
  const durationMs = Date.now() - started;
  if (r.timedOut) return { tool, state: 'timed_out', version, message: 'Stopped at the time limit; its results are not included.', findings: 0, durationMs };
  if (r.spawnError || !okCode(r.code)) return { tool, state: 'failed', version, message: `Exited with code ${r.code ?? 'unknown'}; its results are not included.`, findings: 0, durationMs };
  try {
    const n = parse();
    return { tool, state: 'ran', version, findings: n, durationMs };
  } catch {
    return { tool, state: 'failed', version, message: 'Its output could not be read; its results are not included.', findings: 0, durationMs };
  }
}
