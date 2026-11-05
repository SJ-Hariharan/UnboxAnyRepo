/**
 * Repository investigation: combines the analysers into one result pinned to
 * a commit. Nothing here executes repository code. Network access is limited
 * to the OSV.dev API (fixed host, guarded client) and, through the GitHub
 * client, published repository advisories.
 */
import { analyseGitMeta } from './gitmeta.ts';
import type { AnalysisConfig, Limits } from '../config.ts';
import type { SourceFile, TextStats } from '../source/archive.ts';
import type { AnalysisResult, Finding, FindingStatus, Severity, ToolRun, AdvisoryInfo } from './types.ts';
import { SourceView } from './source.ts';
import { analyseStack } from './stack.ts';
import { analyseStructure } from './structure.ts';
import { analyseInfra, analyseEnv } from './infra.ts';
import { analyseDependencies } from './deps.ts';
import { planLaunch } from './launch.ts';
import { scanSecrets } from './rules/secrets.ts';
import { scanCode } from './rules/code.ts';
import { scanConfig } from './rules/config.ts';
import { sevIndex } from './rules/finding.ts';
import { checkOsv } from './osv.ts';
import { runScanners } from './scanners.ts';
import type { Transport } from '../github/fetcher.ts';

export const DISCLAIMER =
  'Static analysis finds known patterns; it cannot prove that code is safe. No findings does not mean no vulnerabilities. Heuristic findings may be false positives, and results apply only to the commit shown.';

export interface AnalyseInput {
  files: readonly SourceFile[];
  dirs: readonly string[];
  texts: ReadonlyMap<string, Buffer>;
  textStats: TextStats;
  totalBytes: number;
  skippedSymlinks: number;
  repo: { fullName: string; htmlUrl: string; name: string };
  commitSha: string;
  /** Live mode only: published advisories for this repository. */
  listAdvisories?: (signal?: AbortSignal) => Promise<AdvisoryInfo[]>;
}

export interface AnalyseOptions {
  config: AnalysisConfig;
  limits: Pick<Limits, 'scannerTimeoutMs' | 'fetchTimeoutMs'>;
  userAgent: string;
  signal?: AbortSignal;
  osvTransport?: Transport;
}

const METHOD_RANK: Record<Finding['method'], number> = { semgrep: 0, gitleaks: 0, osv: 0, 'github-advisory': 0, 'manifest-analysis': 1, 'builtin-rule': 2 };

/** Drop duplicates of the same issue at the same place, keeping the more precise tool. */
export function dedupe(findings: Finding[]): Finding[] {
  const byId = new Map<string, Finding>();
  for (const f of findings) if (!byId.has(f.id)) byId.set(f.id, f);
  const sorted = [...byId.values()].sort((a, b) => METHOD_RANK[a.method] - METHOD_RANK[b.method]);
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of sorted) {
    const key = f.file && f.startLine && f.method !== 'osv' ? `${f.category}|${f.file}|${f.startLine}` : `id|${f.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  const statusRank: Record<FindingStatus, number> = { confirmed: 0, unverified: 1, heuristic: 2, informational: 3 };
  return groupRepeats(out).sort((a, b) => sevIndex(b.severity) - sevIndex(a.severity) || statusRank[a.status] - statusRank[b.status] || (a.file ?? '').localeCompare(b.file ?? '') || (a.startLine ?? 0) - (b.startLine ?? 0));
}

/** Collapse more than 3 hits of one rule in one file into a single finding that lists the lines. */
export function groupRepeats(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!f.file || f.method === 'osv') continue;
    const k = `${f.ruleId}|${f.file}`;
    const g = groups.get(k);
    if (g) g.push(f);
    else groups.set(k, [f]);
  }
  const drop = new Set<Finding>();
  const replace = new Map<Finding, Finding>();
  for (const g of groups.values()) {
    if (g.length <= 3) continue;
    const sorted = [...g].sort((a, b) => (a.startLine ?? 0) - (b.startLine ?? 0));
    const first = sorted[0] as Finding;
    const lines = sorted.map((f) => f.startLine).filter((n): n is number => n !== undefined);
    replace.set(first, {
      ...first,
      title: `${first.title} (${g.length} matches in this file)`,
      evidence: `${first.evidence ?? ''} — also at lines ${lines.slice(1, 12).join(', ')}${lines.length > 12 ? ', …' : ''}`.slice(0, 400),
    });
    for (const f of sorted.slice(1)) drop.add(f);
  }
  return findings.filter((f) => !drop.has(f)).map((f) => replace.get(f) ?? f);
}

export async function analyseRepository(input: AnalyseInput, opts: AnalyseOptions): Promise<AnalysisResult> {
  const src = new SourceView(input);
  const stack = analyseStack(src);
  const structure = analyseStructure(src, stack.node?.pkg);
  const infra = analyseInfra(src);
  const env = analyseEnv(src, infra);
  const dependencies = analyseDependencies(src, stack);
  const gitMeta = analyseGitMeta(src);
  const { plan, compatibility } = planLaunch({ src, stack, infra, env, repo: input.repo, commitSha: input.commitSha, skippedSymlinks: input.skippedSymlinks, lfs: gitMeta.summary.lfs });

  const local: Finding[] = [...scanSecrets(src), ...scanCode(src), ...scanConfig(stack, infra), ...gitMeta.findings];
  const tools: ToolRun[] = [{ tool: 'Built-in rules', state: 'ran', findings: local.length, message: 'Secrets, insecure code patterns, install scripts, Docker, Compose, GitHub Actions and Git submodule configuration.' }];

  const osvP = opts.config.osv
    ? checkOsv(dependencies.packages, { userAgent: opts.userAgent, timeoutMs: opts.limits.fetchTimeoutMs, ...(opts.signal ? { signal: opts.signal } : {}), ...(opts.osvTransport ? { transport: opts.osvTransport } : {}) })
    : Promise.resolve({ findings: [] as Finding[], tool: { tool: 'OSV.dev', state: 'disabled', message: 'Dependency vulnerability lookup is disabled (offline demo mode or UNBOX_OSV=false).', findings: 0 } as ToolRun });
  const scanP = runScanners(src, opts.config, opts.limits.scannerTimeoutMs);
  const advP: Promise<{ advisories: AdvisoryInfo[]; tool: ToolRun }> =
    opts.config.githubAdvisories && input.listAdvisories
      ? input
          .listAdvisories(opts.signal)
          .then((advisories) => ({ advisories, tool: { tool: 'GitHub repository advisories', state: 'ran', findings: advisories.length } as ToolRun }))
          .catch(() => ({ advisories: [], tool: { tool: 'GitHub repository advisories', state: 'failed', message: 'Published advisories could not be read from GitHub.', findings: 0 } as ToolRun }))
      : Promise.resolve({ advisories: [], tool: { tool: 'GitHub repository advisories', state: 'disabled', message: 'Not queried (offline demo mode or UNBOX_GITHUB_ADVISORIES=false).', findings: 0 } as ToolRun });

  const [osv, scanners, adv] = await Promise.all([osvP, scanP, advP]);
  tools.push(osv.tool, ...scanners.tools, adv.tool);
  const findings = dedupe([...local, ...osv.findings, ...scanners.findings]).slice(0, 600);

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byStatus: Record<FindingStatus, number> = { confirmed: 0, heuristic: 0, informational: 0, unverified: 0 };
  for (const f of findings) {
    bySeverity[f.severity]++;
    byStatus[f.status]++;
  }
  const s = input.textStats;
  return {
    coverage: {
      textFiles: s.collected,
      textBytes: s.collectedBytes,
      skipped: { ...s.skipped },
      complete: s.skipped.budget === 0 && s.skipped.too_large === 0,
    },
    structure,
    stack: stack.stack,
    packageManagers: stack.packageManagers,
    manifests: stack.manifests,
    scripts: stack.scripts.slice(0, 120),
    dockerfiles: infra.dockerfiles,
    compose: infra.compose,
    ci: infra.ci,
    env: env.vars.slice(0, 150),
    tests: stack.tests,
    dependencies: { ...dependencies, packages: dependencies.packages.slice(0, 3000) },
    git: gitMeta.summary,
    compatibility,
    launch: plan,
    findings,
    tools,
    advisories: adv.advisories,
    summary: { bySeverity, byStatus, total: findings.length },
    disclaimer: DISCLAIMER,
  };
}
