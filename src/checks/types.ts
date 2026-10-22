import type { Ecosystem } from '../config.ts';

/** The complete allowlist of checks this version can run. */
export const CHECK_IDS = [
  'node.npm-test',
  'node.npm-build',
  'node.npm-lint',
  'python.pytest',
  'python.unittest',
  'go.test',
  'go.vet',
  'go.build',
  'rust.cargo-test',
  'rust.cargo-build',
] as const;

export type CheckId = (typeof CHECK_IDS)[number];

export function isCheckId(v: unknown): v is CheckId {
  return typeof v === 'string' && (CHECK_IDS as readonly string[]).includes(v);
}

/**
 * none: no network interface at all.
 * registry-proxy: only an operator-provided egress proxy that allowlists
 *                 public package registries is reachable.
 */
export type StepNetwork = 'none' | 'registry-proxy';

export interface StepPlan {
  kind: 'install' | 'check';
  title: string;
  argv: string[];
  env: Record<string, string>;
  network: StepNetwork;
}

export interface RepoScript {
  /** Where the code comes from, e.g. 'package.json → scripts.test'. */
  source: string;
  /** Untrusted text from the repository, cleaned and truncated for display only. */
  text: string;
}

export interface CheckOption {
  id: CheckId;
  ecosystem: Ecosystem;
  title: string;
  summary: string;
  steps: StepPlan[];
  installsDependencies: boolean;
  /** Plain-language statement of which repository code will execute. */
  executes: string;
  repoScripts: RepoScript[];
  notes: string[];
  available: boolean;
  unavailableReason?: string;
}

export type Confidence = 'high' | 'medium' | 'low';

export interface EcosystemFinding {
  ecosystem: Ecosystem;
  label: string;
  confidence: Confidence;
  evidence: string[];
  notes: string[];
}

export interface DetectionResult {
  status: 'checks_available' | 'no_supported_checks' | 'unsupported';
  ecosystems: EcosystemFinding[];
  checks: CheckOption[];
  /** Other ecosystems we noticed but do not support. */
  unsupportedSignals: string[];
  warnings: string[];
}
