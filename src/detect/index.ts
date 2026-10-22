/**
 * Project detection: cautious, root-level, best effort. Pure function of the
 * sanitized file list and the small manifests the archive layer kept.
 */
import { detectNode } from './node.ts';
import { detectPython } from './python.ts';
import { detectGo } from './go.ts';
import { detectRust } from './rust.ts';
import type { DetectInput } from './util.ts';
import { nodeChecks, pythonChecks, goChecks, rustChecks } from '../checks/templates.ts';
import type { DetectionResult, EcosystemFinding, CheckOption } from '../checks/types.ts';

export type { DetectInput } from './util.ts';

const UNSUPPORTED_SIGNALS: [RegExp, string][] = [
  [/^pom\.xml$/, 'Java (Maven)'],
  [/^build\.gradle(\.kts)?$/, 'Java/Kotlin (Gradle)'],
  [/^Gemfile$/, 'Ruby'],
  [/^composer\.json$/, 'PHP'],
  [/^[^/]+\.(csproj|sln|fsproj)$/, '.NET'],
  [/^mix\.exs$/, 'Elixir'],
  [/^Package\.swift$/, 'Swift'],
  [/^CMakeLists\.txt$/, 'C/C++ (CMake)'],
  [/^(deno\.json|deno\.jsonc)$/, 'Deno'],
  [/^pubspec\.yaml$/, 'Dart'],
  [/^(stack\.yaml|[^/]+\.cabal)$/, 'Haskell'],
  [/^(Makefile|makefile|GNUmakefile)$/, 'Makefile (never executed by this tool)'],
  [/^Dockerfile$/, 'Dockerfile (never executed by this tool)'],
];

export function detectProject(input: DetectInput, opts: { goImage: string }): DetectionResult {
  const present = new Set(input.files.map((f) => f.path));
  const ecosystems: EcosystemFinding[] = [];
  const checks: CheckOption[] = [];
  const warnings: string[] = [];

  const node = detectNode(input, present);
  if (node) {
    ecosystems.push({ ecosystem: 'node', label: 'Node.js (npm)', confidence: node.confidence, evidence: node.evidence, notes: node.blocker ? [node.blocker, ...node.notes] : node.notes });
    checks.push(...nodeChecks(node));
  }
  const py = detectPython(input, present);
  if (py) {
    ecosystems.push({ ecosystem: 'python', label: 'Python', confidence: py.confidence, evidence: py.evidence, notes: py.blocker ? [py.blocker, ...py.notes] : py.notes });
    checks.push(...pythonChecks(py));
  }
  const go = detectGo(input, present);
  if (go) {
    ecosystems.push({ ecosystem: 'go', label: 'Go modules', confidence: go.confidence, evidence: go.evidence, notes: go.blocker ? [go.blocker, ...go.notes] : go.notes });
    checks.push(...goChecks(go, opts.goImage));
  }
  const rust = detectRust(input, present);
  if (rust) {
    ecosystems.push({ ecosystem: 'rust', label: 'Rust (Cargo)', confidence: rust.confidence, evidence: rust.evidence, notes: rust.blocker ? [rust.blocker, ...rust.notes] : rust.notes });
    checks.push(...rustChecks(rust));
  }

  const unsupportedSignals: string[] = [];
  for (const [re, label] of UNSUPPORTED_SIGNALS) {
    if ([...present].some((p) => re.test(p)) && !unsupportedSignals.includes(label)) unsupportedSignals.push(label);
  }

  if (ecosystems.length > 1) warnings.push('More than one ecosystem was detected; each check runs only its own toolchain.');
  const nested = input.files.filter((f) => /\/(package\.json|go\.mod|Cargo\.toml|pyproject\.toml)$/.test(f.path) && !f.path.startsWith('node_modules/'));
  if (nested.length > 0) warnings.push('Nested project manifests exist; only the repository root is analysed in this version.');

  const status: DetectionResult['status'] =
    ecosystems.length === 0 ? 'unsupported' : checks.some((c) => c.available) ? 'checks_available' : 'no_supported_checks';
  return { status, ecosystems, checks, unsupportedSignals, warnings };
}
