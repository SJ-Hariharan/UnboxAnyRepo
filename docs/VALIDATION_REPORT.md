> **Historical:** this report describes the RepoRadar MVP before the UnboxAnyRepo work. Configuration names have since changed from `REPORADAR_*` to `UNBOX_*`. The current state is in [RELEASE_REPORT.md](RELEASE_REPORT.md).

# Validation report — 2026-10-22

Takeover validation of the RepoRadar MVP (commit `d2ac666`) on macOS 15 (Darwin 24.5, Apple Silicon), Node.js 22.23.2, npm 10.9.8, Docker Desktop with `runc` only (no gVisor).

## Summary

- Typecheck, all 93 unit/API tests and all 8 browser tests pass, both in the working copy and in a clean checkout installed with `npm ci`.
- The offline demo and live GitHub inspection work in a real browser. Live inspection was tested with `https://github.com/morluto/rea`.
- Execution was **never enabled**. No repository code ran on this machine, in any container, at any point.
- gVisor is not available here, so the sandbox itself (11 real-container tests) is **not verified**. Only the fail-closed behaviour was tested against a real Docker daemon.

## Commands run and results

| Command | Result |
|---|---|
| `node -v` / `npm -v` | v22.23.2 / 10.9.8 (needs ≥ 22.18) |
| `rm -rf node_modules && npm ci` | 6 packages from `package-lock.json` (smol-toml 1.9.1, typescript 6.0.3, playwright 1.64.1, @types/node 26.6.5) |
| `npm run typecheck` | pass, 0 errors |
| `npm test` | 93 / 93 pass |
| `npx playwright install chromium` then `npm run test:e2e` | 8 / 8 pass |
| `npm run test:docker` (no env) | 11 skipped (opt-in) |
| `REPORADAR_TEST_DOCKER=1 REPORADAR_DOCKER_RUNTIME=runsc node --test --test-name-pattern="fails closed\|reports itself available" test/integration/docker.test.ts` | `fails closed when the configured runtime is missing`: **pass**. `runner reports itself available`: fails as expected, because runsc is not installed |
| Clean checkout: copy of tracked files + lockfile, `npm ci`, `npm run check`, `npm run test:e2e` | typecheck pass, 93 / 93, 8 / 8 |
| `PORT=8788 npm run demo` + browser | home page, demo chips, inspect, pinned commit, check plan, "execution disabled" state; no console errors |
| `PORT=8789 npm start` + browser and API, URL `https://github.com/morluto/rea` | default branch resolved to `edccb430c4ace4595ceff71e1b837351e7634938`; 5,416 files (68.1 MB) sanitized in memory; Node.js (high confidence) and Python (low) detected; `npm test` / `npm run build` planned, blocked by disabled execution |

Manual API probes against the running demo server (all refused as intended):

| Probe | Response |
|---|---|
| `POST /api/runs` with a valid inspection while execution is disabled | `execution_unavailable` |
| `POST /api/runs` with an extra `"command"` field | `unexpected_field` |
| `POST /api/inspect` with `Sec-Fetch-Site: cross-site` | `cross_site` (403) |
| URLs `http://169.254.169.254/…`, `github.com.evil.com`, `github.com@evil.com`, `evil.com/github.com/…` | `invalid_url` |

## Changes made

| File | Change |
|---|---|
| `src/server.ts` | A port already in use (or not permitted) now prints one clear line and exits with code 1, instead of crashing with an unhandled `EADDRINUSE` stack trace. Found because an older demo server was still running on 8787. |
| `package-lock.json` | Generated and verified with `npm ci`. **Not committed yet.** |
| `README.md` | Quick start uses `npm ci`; the clone URL is marked as a placeholder; documents `PORT`, `--env-file`, that runs cannot start in demo mode and that run screenshots come from the scripted test runner; test section adds the Playwright install step, image pulling, and what to expect on a Docker host without gVisor; lists all launch placeholders. |
| `.env.example` | Documents the egress proxy's own variables (`REPORADAR_EGRESS_HOST`, `_PORT`, `_ALLOWLIST`). |
| `.github/workflows/ci.yml` | `npm ci` instead of `npm install`. |
| `CONTRIBUTING.md`, `docs/DEPLOYMENT.md`, `docs/LAUNCH.md` | `npm ci` instructions; launch checklist item updated. |

All tests were rerun after these changes (results above).

## Security controls

### Verified here

| Control | How |
|---|---|
| Execution disabled by default; API refuses to start runs | Server startup line, UI, manual API probe |
| Fails closed when gVisor is missing on a real Docker daemon | Real-Docker integration test |
| `runc` refused without the unsafe acknowledgement, and refused when `NODE_ENV=production` | Unit tests (`factory fails closed`) |
| No host-execution path | Code review of `runner/factory.ts`, `runner/docker.ts`, `runner/exec.ts`: only the `docker` CLI is spawned, with argv arrays and `shell: false` |
| Strict GitHub URL parsing; outbound hosts never taken from input | Unit tests + manual probes |
| DNS rebinding / private, loopback, link-local, metadata, CGNAT, IPv4-mapped IPv6 addresses refused at connect time | Unit tests, including a real HTTPS connection to loopback being refused |
| Redirects re-validated per hop (HTTPS, port 443, allowlisted host, no credentials); auth header dropped on cross-host redirect; hop limit | Unit tests + code review |
| Archive sanitization: size, file-count, per-file and decompression caps; traversal, absolute paths, escaping symlinks, hard links, devices rejected; never extracted on the server | Unit tests + code review; a 5,416-file real archive processed correctly |
| Command allowlisting: constant templates, API accepts only known fields and a check id | Unit tests + manual probe |
| CSRF: `SameSite=Strict` cookie, `Origin` / `Sec-Fetch-Site` checks, JSON-only bodies; strict CSP | API tests + manual probe + header review |
| Log sanitization, secret redaction, size caps | Unit tests |
| Timeout, cancellation, watchdog and cleanup *logic* | Unit tests with a fake Docker CLI |
| `docker run` argv always carries: `--runtime`, `--pull never`, `--network none` (checks), non-root `--user`, `--cap-drop ALL`, `no-new-privileges`, `--read-only`, memory (no swap), CPU, PID, ulimits, tmpfs workspace | Unit test of the generated argv + code review |
| Docker CLI gets a minimal environment (no `GITHUB_TOKEN`) | Code review of `minimalEnv` + unit tests |

### Not verified (assumptions)

- **gVisor isolation.** Not installed; macOS Docker Desktop does not provide `runsc`. None of the real-container tests ran.
- **Whether the container flags are actually enforced** at runtime (no network, read-only root, uid, memory/PID/disk limits, process-tree kill on timeout, verified cleanup). Only the generated argv was tested.
- **The runtime check trusts the name.** `status()` only checks that a runtime called `runsc` is registered in `docker info`. A daemon whose `runsc` entry points to another binary would pass. Recommendation: probe once at startup (for example, run a container under `--runtime runsc` and check that `dmesg` reports gVisor).
- **Egress proxy deployment.** The proxy logic is unit-tested; the compose file, the `internal` network and the host firewall were not run.
- **Image pinning by digest**, reverse-proxy settings, rate limits under real load, multi-IP abuse.
- **Linux CI.** The workflow was edited but not run on GitHub.
- The orphan sweeper assumes one RepoRadar process per Docker daemon (documented); a second instance would remove the first one's containers.

## Unresolved items

1. **No `LICENSE` file.** All rights reserved until maintainers choose one (launch blocker).
2. **Placeholder contacts:** `SECURITY-CONTACT@EXAMPLE.COM` in `SECURITY.md`, `CONDUCT-CONTACT@EXAMPLE.COM` in `CODE_OF_CONDUCT.md`, and `<repository-url>` in the README quick start. No real values were invented.
3. `package-lock.json` and the changes above are **not committed**.
4. GitHub Actions are pinned to tags, not commit SHAs (noted in the workflow).
5. Real-container tests still need a Linux host with gVisor.
6. Running a check on `morluto/rea` would also need the dependency egress proxy, because its `npm test` requires `npm ci`.

## How to launch

Inspection only (works on this Mac today):

```sh
cd reporadar
npm ci
npm run demo                 # offline fixtures, http://127.0.0.1:8787
npm start                    # live github.com
PORT=8788 npm start          # if 8787 is taken
```

Running checks (requires a Linux sandbox host; not tested here):

```sh
# sandbox host
sudo runsc install && sudo systemctl restart docker
docker run --rm --runtime=runsc hello-world
node scripts/pull-images.ts
docker compose -f deploy/compose.sandbox-host.yml up -d     # optional: dependency downloads

# verify the sandbox before trusting it
REPORADAR_TEST_DOCKER=1 REPORADAR_DOCKER_RUNTIME=runsc npm run test:docker

# server
REPORADAR_RUNNER=docker REPORADAR_DOCKER_RUNTIME=runsc \
REPORADAR_FETCH_NETWORK=reporadar-fetch REPORADAR_FETCH_PROXY_URL=http://reporadar-egress:3128 \
npm start
```
