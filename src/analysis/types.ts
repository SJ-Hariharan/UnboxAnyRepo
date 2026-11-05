/**
 * Data model for a repository investigation. Everything here is derived from
 * the sanitized snapshot without executing repository code, and is pinned to
 * one commit.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';

/**
 * confirmed     — the fact was established directly (exact package version in
 *                 a lockfile matched an advisory; a config value is present).
 * heuristic     — a pattern matched; it may be a false positive.
 * informational — notable, but not a vulnerability by itself.
 * unverified    — could be real but could not be established (e.g. a version
 *                 range, or a secret-looking string that may be a placeholder).
 */
export type FindingStatus = 'confirmed' | 'heuristic' | 'informational' | 'unverified';

export type DetectionMethod = 'builtin-rule' | 'semgrep' | 'gitleaks' | 'osv' | 'github-advisory' | 'manifest-analysis';

export type FindingCategory =
  | 'secret'
  | 'command-injection'
  | 'code-execution'
  | 'sql-injection'
  | 'deserialization'
  | 'path-traversal'
  | 'install-script'
  | 'vulnerable-dependency'
  | 'docker'
  | 'ci'
  | 'network'
  | 'auth'
  | 'crypto'
  | 'configuration'
  | 'other';

export interface Finding {
  /** Stable across re-inspections of the same content: rule + file + normalized evidence. */
  id: string;
  ruleId: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  file?: string;
  startLine?: number;
  endLine?: number;
  /** Short excerpt, secrets redacted, control characters removed. */
  evidence?: string;
  risk: string;
  remediation: string;
  method: DetectionMethod;
  references: string[];
  cwe?: string;
  package?: { ecosystem: string; name: string; version: string; fixedIn?: string[] };
}

export type ToolState = 'ran' | 'not_installed' | 'disabled' | 'failed' | 'timed_out' | 'skipped';

export interface ToolRun {
  tool: string;
  state: ToolState;
  version?: string;
  message?: string;
  findings: number;
  durationMs?: number;
}

export interface LanguageShare {
  name: string;
  files: number;
  bytes: number;
  percent: number;
}

export interface StructureSummary {
  fileCount: number;
  dirCount: number;
  totalBytes: number;
  topLevel: { name: string; kind: 'dir' | 'file'; files: number }[];
  languages: LanguageShare[];
  entryPoints: { path: string; reason: string }[];
}

export interface StackItem {
  name: string;
  kind: 'framework' | 'library' | 'tool' | 'runtime' | 'database' | 'service';
  ecosystem?: string;
  version?: string;
  evidence: string;
}

export interface PackageManagerInfo {
  name: string;
  ecosystem: string;
  evidence: string;
  lockfile?: string;
}

export interface ManifestInfo {
  path: string;
  kind: string;
  lockfile: boolean;
}

export type ScriptKind = 'lifecycle' | 'start' | 'dev' | 'build' | 'test' | 'lint' | 'other';

export interface ScriptInfo {
  source: string;
  name: string;
  command: string;
  kind: ScriptKind;
}

export interface DockerfileInfo {
  path: string;
  baseImages: string[];
  exposes: number[];
  user?: string;
  stages: number;
}

export interface ComposeInfo {
  path: string;
  services: { name: string; image?: string; build: boolean; ports: string[]; dependsOn: string[] }[];
}

export interface CiInfo {
  path: string;
  provider: string;
  jobs: string[];
  triggers: string[];
}

export interface EnvVarInfo {
  name: string;
  /** Up to 5 places it was seen, as path:line. */
  sources: string[];
  documented: boolean;
}

export interface TestInfo {
  frameworks: string[];
  configFiles: string[];
  testFiles: number;
  commands: { command: string; source: string }[];
}

/** OSV.dev ecosystem names. */
export type DependencyEcosystem = 'npm' | 'PyPI' | 'Go' | 'crates.io' | 'RubyGems' | 'Packagist' | 'NuGet' | 'Pub';

export interface DependencyPackage {
  ecosystem: DependencyEcosystem;
  name: string;
  version: string;
  /** The version is exact (from a lockfile or an == pin), not a range. */
  exact: boolean;
  source: string;
}

export interface DependencySummary {
  packages: DependencyPackage[];
  byEcosystem: Record<string, number>;
  lockfiles: string[];
  /** Notes such as "no lockfile: versions are ranges". */
  notes: string[];
  truncated: boolean;
}

export type SubmoduleUrlKind = 'https' | 'ssh' | 'http' | 'git-protocol' | 'relative' | 'local' | 'ext-transport' | 'option-like' | 'other' | 'missing';

export interface SubmoduleInfo {
  name: string;
  path?: string;
  url?: string;
  branch?: string;
  urlKind: SubmoduleUrlKind;
  /** Line of the [submodule] header in .gitmodules. */
  line: number;
}

export interface LfsPointer {
  path: string;
  /** Size of the real object in bytes, from the pointer. */
  size: number;
}

/** What GitHub archives leave out: submodule contents and Git LFS objects. */
export interface GitMetaSummary {
  submodules: SubmoduleInfo[];
  lfs: { patterns: string[]; pointers: LfsPointer[]; pointerCount: number; pointerBytes: number };
}

export interface CompatibilityNote {
  level: 'blocker' | 'warning' | 'info';
  message: string;
  evidence?: string;
}

export type ProjectKind =
  | 'static-site'
  | 'vite'
  | 'nextjs'
  | 'create-react-app'
  | 'frontend-other'
  | 'node-server'
  | 'node-library'
  | 'python-web'
  | 'python-app'
  | 'python-library'
  | 'docker'
  | 'compose'
  | 'go'
  | 'rust'
  | 'unknown';

export interface LaunchStep {
  title: string;
  commands: string[];
  note?: string;
}

export interface PreviewPlan {
  /** static: served from the snapshot; build: needs a sandboxed build first; none: not previewable. */
  kind: 'static' | 'build' | 'none';
  /** Directory inside the repository that is served (static) or produced (build). */
  root?: string;
  /** Check that produces the output for build previews. */
  buildCheckId?: string;
  reason: string;
}

export interface LaunchPlan {
  kinds: ProjectKind[];
  primary: ProjectKind;
  summary: string;
  packageManager?: string;
  ports: { port: number; source: string }[];
  services: { name: string; source: string }[];
  envFile?: string;
  requiredEnv: string[];
  steps: LaunchStep[];
  warnings: string[];
  preview: PreviewPlan;
}

export interface AdvisoryInfo {
  id: string;
  severity: string;
  summary: string;
  url: string;
}

export interface AnalysisResult {
  coverage: {
    textFiles: number;
    textBytes: number;
    skipped: Record<string, number>;
    complete: boolean;
  };
  structure: StructureSummary;
  stack: StackItem[];
  packageManagers: PackageManagerInfo[];
  manifests: ManifestInfo[];
  scripts: ScriptInfo[];
  dockerfiles: DockerfileInfo[];
  compose: ComposeInfo[];
  ci: CiInfo[];
  env: EnvVarInfo[];
  tests: TestInfo;
  dependencies: DependencySummary;
  git: GitMetaSummary;
  compatibility: CompatibilityNote[];
  launch: LaunchPlan;
  findings: Finding[];
  tools: ToolRun[];
  advisories: AdvisoryInfo[];
  summary: {
    bySeverity: Record<Severity, number>;
    byStatus: Record<FindingStatus, number>;
    total: number;
  };
  /** Plain statement shown with every result; never "safe". */
  disclaimer: string;
}
