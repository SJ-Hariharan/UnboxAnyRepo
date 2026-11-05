# Release readiness report — UnboxAnyRepo 0.2.0 (2026-10-24)

Work done on top of commit `2b9f8e8` (the validated RepoRadar MVP) on macOS 15.5 (Apple Silicon), Node.js 22.23.2, Docker Desktop 29.7.2 with `runc` only. The code is in commit `4b1b442`; release documentation was completed in the following commit and pushed to <https://github.com/SJ-Hariharan/UnboxAnyRepo> on 2026-11-05. No release tag, package or deployment has been published.

## 1. Files changed

About 105 files: 55 modified, the rest new (plus 16 regenerated screenshots).

- **New code:**
  - `src/brand.ts`
  - `src/analysis/` (14 files)
  - `src/preview/store.ts`
  - `src/report/report.ts`
  - `src/runner/verify.ts`
  - `scripts/sandbox.ts`
  - `rules/semgrep/unboxanyrepo.yml`
- **Changed code:**
  - `src/app.ts`, `src/config.ts`, `src/inspect.ts`
  - `src/github/client.ts`, `src/github/fetcher.ts`, `src/http/util.ts`
  - `src/runner/docker.ts`, `src/runner/factory.ts`, `src/runner/types.ts`
  - `src/runs/inspections.ts`, `src/runs/manager.ts`
  - `src/source/archive.ts`, `src/text.ts`
  - the `UNBOX_` renames
- **UI:** `public/index.html`, `public/app.js`, `public/styles.css`, `public/favicon.svg`.
- **Tests:**
  - New: `test/unit/analysis.test.ts`, `osv-report.test.ts`, `preview.test.ts`, `scanners.test.ts`, `verify.test.ts`, `test/api/investigation.test.ts`, `test/helpers/analysis.ts`.
  - Extended: `test/e2e/ui.test.ts`, `test/integration/docker.test.ts`, `test/helpers/fake-docker.ts`, `test/helpers/fake-runner.ts`, `test/unit/runner.test.ts`.
- **Fixtures:** `fixtures/demo-repos/static-site`, `vite-app`, `flask-app`, `risky-node-api`.
- **Release and deployment:** `LICENSE`, `render.yaml`, `Dockerfile`, `.dockerignore`, `.github/workflows/ci.yml`, `.env.example`, `package.json`/`package-lock.json` (adds `yaml`).
- **Docs:**
  - `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, new `CHANGELOG.md`
  - new `docs/API.md` (HTTP API reference) and `docs/README.md` (index)
  - `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/DEPLOYMENT.md`, `docs/LAUNCH.md`
  - new `docs/SUPPORTED.md`
- **Rebrand:** RepoRadar → UnboxAnyRepo. The config prefix changed from `REPORADAR_` to `UNBOX_`, plus the Docker labels and the demo owner.

## 2. Features implemented

- **Investigation (no code execution):**
  - Identity and commit pinning.
  - Languages, structure and entry points; stack and frameworks; package managers.
  - Manifests, lockfiles and an exact-version inventory (npm/Yarn/pnpm/Bun, pip/Poetry/uv/Pipenv, Go, Cargo).
  - Scripts, with lifecycle scripts highlighted.
  - Dockerfiles, Compose files and CI.
  - Environment variable *names* only.
  - Test tooling and compatibility notes.
  - Analysis coverage that shows what was skipped.
- **Security analysis:**
  - **Built-in rules:** secrets (redacted), command and SQL injection, eval, unsafe deserialization, path traversal, TLS/CORS/JWT/debug settings, weak password hashing, install scripts, Docker, Compose, and GitHub Actions permissions, injection and pinning.
  - **OSV.dev lookup:** exact versions only, aliases de-duplicated, fixed versions.
  - **Optional Semgrep:** project-owned rules, no registry.
  - **Optional Gitleaks:** redacted.
  - **GitHub repository advisories.**
  - **Every finding has:** a stable ID, severity, confidence, status, location, evidence, risk, remediation, method and references.
  - **Every tool reports its state:** ran, not installed, failed, timed out, disabled or skipped.
- **Launch planning:** project kind, and setup commands from templates (installs with scripts disabled). Also env-file and backing-service steps, ports, required services, and preview eligibility.
- **Reports:** Markdown and JSON downloads, with hostile text escaped and secrets redacted.
- **Previews:**
  - Static previews from the snapshot. Each runs on its own site (`<token>.preview.localhost` locally, a configurable wildcard domain in production) under a CSP sandbox, with a path-based fallback.
  - Health checks, expiry, stop/restart, per-session and memory limits.
  - Build previews collect output from the sandbox; this needs a verified sandbox.
- **Sandbox gate:** gVisor runs need both a live gVisor kernel probe and a recorded passing run of the real-container tests for the same host and images. `npm run sandbox` reports PASS/FAIL/BLOCKED/NOT RUN/UNKNOWN. Seven new real-container tests were added (host isolation, network/metadata/private-range denial, failure cleanup, crash sweep, missing image, concurrent workspaces, egress proxy).
- **Dashboard:** a new responsive UI with section navigation, real counts only (no scores), filters, a live preview frame, a report section, and accessible controls.
- **Deployment:** an inspection-only Render blueprint and container image.

## 3. Test commands and results

| Command | Result |
|---|---|
| `npm run typecheck` | pass |
| `npm test` | **134 / 134 pass**, 0 skipped. Includes a real Semgrep 1.182.0 + Gitleaks 8.30.1 run (both installed with Homebrew for this work) |
| `npx playwright install chromium && npm run test:e2e` | **11 / 11 pass** |
| `npm run test:docker` | 18 / 18 **skipped**: opt-in, and gVisor is not available here (**NOT RUN**) |
| `npm run sandbox -- --verify` | Docker PASS; gVisor FAIL (not installed); images FAIL (not pulled); probe and tests BLOCKED; no record written; execution disabled |
| Clean checkout (`git ls-files` copy) + `npm ci`, typecheck, `npm test`, browser tests | pass (134 / 11) |
| `npm ci --omit=dev` + `NODE_ENV=production node src/server.ts` | starts; `/healthz` ok; execution disabled; `Secure` session cookie |
| `docker build` of the `Dockerfile` + run | healthy; runs as `node`; no Docker CLI or socket in the image (image removed afterwards) |
| Live: `UNBOX_OSV=true npm run demo` | OSV returned 7 distinct advisories for `flask==2.0.1` / `requests==2.19.0` and 2 for `express@4.17.1`, with fix versions |
| Live UI: inspect `https://github.com/morluto/rea` | 33 s for 5,903 files; OSV checked 920 packages (5 advisories); Semgrep and Gitleaks ran; 36 findings after grouping; report downloaded; no console errors |
| Real Chromium: static preview | renders inside the dashboard; absolute-path assets load; the page cannot read cookies or storage, or call the app's API |

## 4. Security controls: verified versus unverified

**Verified here** (by tests or direct observation):
- Analysis and previews never execute repository code.
- Secret and environment values are redacted or never stored.
- Report escaping works.
- YAML alias bombs are rejected.
- Scanner output cannot place files outside its temp directory, and missing scanners are reported.
- OSV requests: fixed host, no POST redirects, failures reported.
- Preview isolation, checked in real Chromium:
  - pages run in an opaque origin;
  - the preview host serves no app or API;
  - no cookies are set or accepted;
  - traversal attempts return 404;
  - previews are owned by one session and expire.
- The verification gate refuses execution when:
  - the `runsc` runtime is not gVisor;
  - there is no verification record;
  - the record is stale or names a different host;
  - images have changed;
  - any test in the record did not pass.
  These cases were tested with a fake Docker, plus a real Docker without gVisor.
- Earlier controls still pass (URL/SSRF/DNS, archive sanitization, CSRF, session ownership, runner argv hardening).

**Not verified:**
- gVisor isolation and every real-container test: no Linux gVisor host was available.
- Build previews with a real build.
- The egress proxy deployment and the host firewall.
- Behaviour on the Render free tier, including `X-Forwarded-For` handling.
- Wildcard preview domains with TLS.
- Safari's handling of `*.localhost` (the alternative link exists for that case).
- Semgrep/Gitleaks robustness against crafted files.
- CI on GitHub: the workflow was written but not run.

## 5. Live previews

They work for **static sites** and **committed build output**, tested with the `static-site` fixture in a real browser and in API tests.

**Build previews** (Vite, CRA, other front-ends, Next.js static export) are implemented end to end and tested with a scripted runner. They are **not available on this machine**, because they need a verified gVisor sandbox. **Server apps are not previewable**; by design they get setup steps instead.

## 6. Public deployment

**Not done.** `render.yaml` and the `Dockerfile` are prepared, and the image was tested locally. No account was created and nothing was deployed.

## 7. Remaining infrastructure dependencies

- **For execution and build previews:** a Linux machine with Docker and gVisor (a VM is fine), the sandbox images pulled (ideally pinned by digest), optionally the egress proxy, and a passing `npm run sandbox -- --verify`. This cannot be done on Docker Desktop for macOS.
- **For a public instance:** a hosting account (for example Render's free plan) and a `GITHUB_TOKEN` with no permissions. Optionally, a wildcard preview domain with TLS.

## 8. Remaining release blockers

Resolved since the first draft of this report: the code is committed; the repository URL, security contact and conduct contact now point to the GitHub repository and its maintainer; the name is the repository's name.

1. **GitHub private vulnerability reporting** must be enabled in the repository settings; `SECURITY.md` links to it.
2. **CI** must pass on GitHub (see the Actions tab after the push).
3. The **real-container tests have never run on gVisor**, so execution stays off everywhere until `npm run sandbox -- --verify` passes on a Linux gVisor host.
4. The `LICENSE` copyright holder is "The UnboxAnyRepo contributors". Replace it with a person or organisation if you prefer.
5. Domain, handle and trademark availability of "UnboxAnyRepo" is unchecked.
6. No `v0.2.0` tag or GitHub release exists yet.

## 9. Next actions for the maintainer

1. Check the Actions tab: both CI jobs should be green. Fix anything Linux-specific that fails.
2. Enable private vulnerability reporting, and set the description and topics from `docs/LAUNCH.md`.
3. Tag `v0.2.0` and publish release notes from `CHANGELOG.md`.
4. To publish an inspection-only demo: create a Render account and apply `render.yaml`. Then add `GITHUB_TOKEN`, set `UNBOX_PUBLIC_ORIGIN`, and test it.
5. To offer execution: provision a Linux + gVisor host, then run `node scripts/pull-images.ts` and `npm run sandbox -- --verify` there.
