# Launch checklist and plan

## Before making the repository public

- [x] License: MIT `LICENSE` added (copyright "The UnboxAnyRepo contributors"). Replace the holder with a person or organisation if preferred, and confirm you have the right to license all contributions.
- [ ] Decide whether to keep the provisional name; check domain, handle and trademark availability yourself.
- [ ] Replace the security contact placeholder in `SECURITY.md`, and enable GitHub private vulnerability reporting.
- [ ] **Commit `package-lock.json`** (generated and verified with `npm ci`; CI already uses `npm ci`).
- [ ] Pin sandbox images by digest in your deployment, and pin GitHub Actions to commit SHAs.
- [ ] Run `npm run check` and `npm run test:e2e`; and, if execution will be offered, `npm run sandbox -- --verify` on a real Linux + gVisor host.
- [ ] Deploy an inspection-only instance (`render.yaml` or the `Dockerfile`) and test it end to end: health check, live inspection, report download, static preview.
- [ ] If you host execution for others: follow `docs/DEPLOYMENT.md` exactly (dedicated sandbox VM, firewall, gVisor, reverse-proxy rate limits), and read `docs/THREAT_MODEL.md` once more.
- [ ] Regenerate screenshots with `npm run screenshots`; keep the caption explaining they use the scripted runner.
- [ ] Set the repository description, topics, social preview image and a pinned "Roadmap" discussion.

## Repository description

> From GitHub link to running project: understand any public repository before you clone it — stack, setup steps, security findings, dependency vulnerabilities, live previews of static sites, and a downloadable report. Nothing is executed outside a verified sandbox.

Suggested topics: `developer-tools`, `static-analysis`, `security`, `github`, `onboarding`, `sandbox`, `gvisor`, `nodejs`, `typescript`.

## Safe demo repositories

The bundled fixtures in `fixtures/demo-repos/` are small and written for this project. All except `risky-node-api` and `flask-app` are safe to execute; those two contain deliberately insecure patterns for the analysis demo and are never run by any test. They power `npm run demo`, the browser tests and the screenshots:

| Fixture | Shows |
|---|---|
| `node-hello` | A passing `npm test` with no dependencies |
| `node-failing` | A failing test and how failure is reported |
| `node-with-deps` | A check that needs the registry proxy and a second confirmation |
| `python-hello` | `unittest` discovery |
| `go-hello` | `go test` fully offline |
| `rust-hello` | `cargo test` without dependencies |
| `makefile-only` | The "unsupported" state (Makefiles are never run) |
| `static-site` | A live static preview |
| `vite-app` | A project that needs a sandboxed build before it can be previewed |
| `flask-app` | Setup planning with PostgreSQL, Docker and Compose, plus configuration findings |
| `risky-node-api` | Security findings: injection, install scripts, CI permissions and injection (never executed) |

If you want live examples on a public instance, choose small, well-known repositories you have checked yourself, and present them as examples, not endorsements.

## Announcement draft

> **UnboxAnyRepo: from GitHub link to running project**
>
> I built a tool for the first ten minutes with an unfamiliar repository. Paste a public GitHub URL and UnboxAnyRepo pins the exact commit, reads the code without running it, and shows the stack, entry points, scripts, environment variables, Docker/Compose/CI setup, dependency vulnerabilities (OSV.dev), and security findings with evidence and fixes. It writes the setup commands for your machine (with install scripts disabled), previews static sites live in an isolated origin, and exports everything as a Markdown/JSON report.
>
> What it is not: a guarantee. Static analysis misses things and flags false positives, and every finding says whether it is confirmed or a heuristic. Running code needs a gVisor sandbox that has passed real-container tests; the public demo has execution turned off.
>
> MIT licensed. Feedback on the analysis rules and on which project types to support next is very welcome.

## Where to share

Only in places where self-promotion is allowed, following each community's rules, and once per place:

- "Show HN" on Hacker News (one post, stay to answer questions);
- relevant subreddits that explicitly allow project posts, in their designated threads;
- your own blog, newsletter and social accounts;
- the gVisor and container-security communities, framed as a design to critique.

Do not use bots, alternate accounts, vote rings, paid or incentivized stars, or cross-posting spam. Do not claim the tool makes code "safe".

## Community basics in this repository

- `CONTRIBUTING.md`: setup, tests, and the rules for security-sensitive changes;
- `CODE_OF_CONDUCT.md`: expected behaviour and enforcement;
- `SECURITY.md`: private vulnerability reporting (placeholder contact to fill in);
- `.github/ISSUE_TEMPLATE/`: bug report, feature request, ecosystem template request;
- `.github/PULL_REQUEST_TEMPLATE.md`: includes a security checklist.

## After launch

Measure usefulness, not vanity: which ecosystems people inspect, how often detection says "unsupported", and which checks fail for environmental reasons. Let that drive the roadmap in the README.
