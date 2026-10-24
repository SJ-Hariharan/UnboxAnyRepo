# Contributing to UnboxAnyRepo

Thank you for helping. UnboxAnyRepo handles untrusted repositories, so the bar for changes to its security boundaries is high, and the bar for everything else is "clear, tested and small".

## Setup

```sh
npm ci
npm run demo        # http://127.0.0.1:8787 with bundled fixtures, no GitHub access needed
npm run check       # typecheck + unit + API tests
npx playwright install chromium && npm run test:e2e
```

Node.js 22.18+ runs the TypeScript sources directly; there is no build step. Use only erasable TypeScript syntax (no `enum`, no parameter properties, no namespaces) and import local files with their `.ts` extension.

Optional: install Semgrep and Gitleaks so the real-scanner test runs (it is skipped otherwise).

Real-container tests need a Linux host with Docker and gVisor. Run them through the diagnostic command, which refuses to run them under `runc`:

```sh
npm run sandbox -- --verify
```

## Ground rules

- **No new commands from repository content.** Commands live only in `src/checks/templates.ts` as constant argv arrays. Never interpolate repository text, URLs or user input into a command, and never use a shell.
- **Fail closed.** If something needed for safe execution is missing, report "unavailable" with a reason. Do not add fallbacks to weaker isolation.
- **Treat every input as hostile:** request bodies, GitHub responses, archive entries, manifests, logs.
- **No `innerHTML`** (or equivalents) in the UI for anything that is not a constant.
- **Keep dependencies minimal.** Explain any new runtime dependency in the pull request.
- **Be honest in the UI and docs.** No simulated progress, no scores, no claims that a repository is safe. A tool that did not run must say so.
- **Never execute repository content during analysis or preview.** Analysers read text; they never evaluate, import, build or install anything.
- **Never store secret values.** Redact evidence before it leaves the rule, and never read environment values into results.

## Adding an analysis rule

1. Built-in rules live in `src/analysis/rules/` (secrets, code, configuration); Semgrep rules in `rules/semgrep/unboxanyrepo.yml` (validate with `semgrep scan --validate --config rules/semgrep/unboxanyrepo.yml`).
2. Give the rule a stable id, a CWE where one fits, a plain-language risk and remediation, and the right status: `confirmed` only for facts read directly from configuration or advisory data, `heuristic` for pattern matches.
3. Add tests in `test/unit/analysis.test.ts` for a true positive, a near miss that must not match, and test-code downgrading where relevant.
4. Add or extend a demo fixture only with obviously fake values, and never with real-format credentials.

## Adding an ecosystem or check

1. Add a detector in `src/detect/` that returns typed facts. Read only small, allowlisted root files via `isManifestPath` in `src/source/archive.ts`.
2. Add templates in `src/checks/templates.ts` and the id to `CHECK_IDS`.
3. Add fixtures to `test/fixtures/detection.ts`: valid, malformed, oversized, ambiguous and adversarial.
4. Document the exact commands in the README table.
5. If it needs a registry, add the host to the egress proxy's default allowlist and explain why.

## Pull requests

Keep them focused, include tests, update the docs you touch, and fill in the security checklist in the PR template. By contributing you agree that your contribution is provided under the project's license once one is chosen (see README).
