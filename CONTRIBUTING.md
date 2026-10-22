# Contributing to RepoRadar

Thank you for helping. RepoRadar runs untrusted code, so the bar for changes to its security boundaries is high, and the bar for everything else is "clear, tested and small".

## Setup

```sh
npm ci
npm run demo        # http://127.0.0.1:8787 with bundled fixtures, no GitHub access needed
npm run check       # typecheck + unit + API tests
npx playwright install chromium && npm run test:e2e
```

Node.js 22.18+ runs the TypeScript sources directly; there is no build step. Use only erasable TypeScript syntax (no `enum`, no parameter properties, no namespaces) and import local files with their `.ts` extension.

To run real-container tests you need Docker, ideally with gVisor:

```sh
REPORADAR_TEST_DOCKER=1 REPORADAR_DOCKER_RUNTIME=runsc npm run test:docker
```

## Ground rules

- **No new commands from repository content.** Commands live only in `src/checks/templates.ts` as constant argv arrays. Never interpolate repository text, URLs or user input into a command, and never use a shell.
- **Fail closed.** If something needed for safe execution is missing, report "unavailable" with a reason. Do not add fallbacks to weaker isolation.
- **Treat every input as hostile:** request bodies, GitHub responses, archive entries, manifests, logs.
- **No `innerHTML`** (or equivalents) in the UI for anything that is not a constant.
- **Keep dependencies minimal.** Explain any new runtime dependency in the pull request.
- **Be honest in the UI and docs.** No simulated progress, no claims that a repository is safe.

## Adding an ecosystem or check

1. Add a detector in `src/detect/` that returns typed facts. Read only small, allowlisted root files via `isManifestPath` in `src/source/archive.ts`.
2. Add templates in `src/checks/templates.ts` and the id to `CHECK_IDS`.
3. Add fixtures to `test/fixtures/detection.ts`: valid, malformed, oversized, ambiguous and adversarial.
4. Document the exact commands in the README table.
5. If it needs a registry, add the host to the egress proxy's default allowlist and explain why.

## Pull requests

Keep them focused, include tests, update the docs you touch, and fill in the security checklist in the PR template. By contributing you agree that your contribution is provided under the project's license once one is chosen (see README).
