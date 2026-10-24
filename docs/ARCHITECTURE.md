# Architecture

UnboxAnyRepo is one Node.js process (no framework; runtime dependencies: `smol-toml`, `yaml`) that serves a static UI and a JSON API. TypeScript runs directly through Node's type stripping; there is no build step.

```
Browser (app origin) ──HTTPS──▶ UnboxAnyRepo server
   │                               │ 1. validate URL, pin commit        ──▶ api.github.com, codeload.github.com
   │                               │ 2. sanitize archive in memory          (fixed hosts, HTTPS:443, public IPs only)
   │                               │ 3. analyse (static)                ──▶ api.osv.dev (exact versions only)
   │                               │      └─ optional: Semgrep, Gitleaks on a private temp copy of text files
   │                               │ 4. report (Markdown / JSON)
   │                               │ 5. static preview from the snapshot
   │                               │ 6. checks / build previews ────────▶ Docker CLI ──▶ sandbox host (gVisor), only if verified
   │
Browser (preview origin: <token>.<preview-domain>, opaque origin via CSP sandbox)
   └── receives only preview files; never the app, the API or a session cookie
```

## Trust boundaries

| Boundary | Treated as | Controls |
|---|---|---|
| Browser → server | hostile | strict URL parsing, JSON-only bodies with allowlisted fields, CSRF checks, per-session ownership of every object, rate limits |
| GitHub → server | hostile | fixed hosts, DNS-pinned public IPs, re-validated redirects, size/time caps, field validation |
| Archive contents | hostile | streaming sanitizer: traversal/symlink/device/hard-link rejection, size and count caps; never extracted on the server (except the scanner temp copy, below) |
| Repository files → analysers | hostile | bounded reads, YAML alias limits, TOML/JSON parse errors reported, no evaluation of any content |
| Scanner temp copy | hostile data on disk | fresh 0700 directory, files written exclusively from validated paths, minimal environment, timeout kills the process group, always deleted |
| OSV.dev → server | untrusted data | fixed host, POST without redirects, size caps; only https references are linked |
| Preview content → browser | hostile code | separate origin when configured; `Content-Security-Policy: sandbox` without `allow-same-origin` (opaque origin); no cookies set or accepted; capability tokens that expire |
| Server → sandbox | trusted commands, hostile output | constant argv templates; see the runner below |

## Modules

| Path | Responsibility |
|---|---|
| `src/brand.ts` | Product name, tagline, description, version (one place to rename) |
| `src/config.ts` | All environment configuration, validated at startup |
| `src/github/` | URL parsing, guarded HTTPS client (also used for OSV), GitHub API client |
| `src/source/` | tar reader/writer and the archive sanitizer; collects bounded text for analysis (code first, docs/data in a smaller budget) |
| `src/detect/`, `src/checks/` | ecosystem detection and the allowlisted check templates (for sandbox checks) |
| `src/analysis/` | the investigation: `stack`, `structure`, `infra` (Docker/Compose/CI/env), `deps` (lockfiles), `launch` (setup plan, ports, services, preview eligibility, compatibility), `rules/` (secrets, code, configuration), `osv`, `scanners`, `index` (orchestration, de-duplication, grouping) |
| `src/report/` | Markdown and JSON reports with escaping of all repository text |
| `src/preview/` | preview store (tokens, ownership, expiry, memory caps), tar extraction for previews, health checks, response headers |
| `src/runner/` | sandbox runner interface, Docker implementation, factory (fails closed), verification (gVisor probe + recorded test run) |
| `src/runs/` | run lifecycle, queue, logs (sanitized, redacted, capped), inspection store |
| `src/app.ts` | HTTP routing, preview hosts, SSE |
| `scripts/sandbox.ts` | operator diagnostics and verification (`npm run sandbox`) |
| `public/` | UI (plain DOM, text-only insertion, strict CSP) |

## Analysis pipeline

1. **Snapshot.** The archive is sanitized once. Text files up to `UNBOX_ANALYSIS_MAX_FILE_KB` are kept until `UNBOX_ANALYSIS_MAX_TOTAL_MB`; docs, data and fixtures share a quarter of that budget so they cannot crowd out source code; lockfiles get a larger per-file allowance. Coverage (what was skipped and why) is part of the result.
2. **Facts.** Stack, structure, scripts, Docker/Compose/CI, environment variable names, tests, dependency inventory.
3. **Plan.** Project kind, local setup commands from fixed templates (never from README files), ports, backing services, compatibility notes, preview eligibility.
4. **Findings.** Built-in rules always run. OSV.dev, GitHub advisories, Semgrep and Gitleaks run when enabled and available; each reports `ran`, `not_installed`, `disabled`, `failed`, `timed_out` or `skipped`, and nothing falls back silently. Findings get stable IDs (rule + file + normalized evidence), are de-duplicated (the more precise tool wins), repeated matches in one file are grouped, and secrets are redacted before they are stored.

## Previews

- **Static:** files under the preview root of the sanitized snapshot are held in memory and served read-only.
- **Build:** a build check runs in the verified sandbox; afterwards a constant `tar -c` container copies the output directory out (size-capped), and it is served the same way. Without a verified sandbox this path is unavailable.
- **Not supported:** server applications (they need a long-running process with network access).
- Each preview has a 128-bit token, an owning session, an expiry, stop/restart, a per-session limit and a global memory cap. On a preview host only that preview's files are served; the app and API are not reachable there.

## Runner and verification

`createRunner` returns a disabled runner unless `UNBOX_RUNNER=docker`. With `runsc`, `status()` additionally requires:

1. a live probe: a constant container under `--runtime runsc` prints its kernel log, which must identify gVisor; and
2. a verification record written by `npm run sandbox -- --verify` after every required real-container test passed, for the same Docker host, runtime and image IDs, newer than `UNBOX_SANDBOX_VERIFICATION_MAX_AGE_DAYS`.

The record cannot be produced by configuration. Changing or re-pulling an image disables that ecosystem until verification is repeated. `runc` remains a labelled development mode (explicit acknowledgement, refused in production) and can never be verified.

## State

All state is in memory: inspections (15 min), previews (30 min), runs (1 h), sessions and rate limits. Run exactly one process. Nothing is written to disk except the scanner temp copy (deleted after each scan) and the verification record (written only by the operator command).
