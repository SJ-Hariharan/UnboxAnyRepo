# Threat model

UnboxAnyRepo reads arbitrary public repositories, analyses them, serves previews of their web pages and, where a verified sandbox exists, runs allowlisted checks. This document assumes that every repository is malicious and that some users are abusive.

## Assets

| Asset | Why it matters |
|---|---|
| Sandbox host and its neighbours | Compromise gives an attacker a machine and a network position. |
| Application secrets (GitHub token, TLS keys, cloud credentials) | Allow impersonation or access to other systems. |
| Other users' runs, logs and inspections | Confidentiality between sessions. |
| Internal network and cloud metadata endpoints | Classic SSRF and lateral-movement targets. |
| Service availability and cost | Compute, bandwidth and GitHub rate limits are finite. |
| User trust | A result that implies "this repository is safe" would be harmful. |

## Trust boundaries

1. **Browser → server.** All request data is untrusted: URLs, ids, JSON bodies, headers.
2. **GitHub → server.** Metadata and archives are untrusted, including names, descriptions, branch names, file paths, symlinks and manifest contents.
3. **Server → sandbox.** The server sends a sanitized archive and a constant command; it receives untrusted bytes back (exit codes, logs).
4. **Sandbox → network.** Check steps have no network. Install steps can reach only an egress proxy that allowlists public package registries.
5. **Server → Docker daemon.** Whoever controls the Docker API controls the sandbox host, so the server and the sandbox host must be operated as one trust domain, or the daemon placed on a dedicated host reached with `UNBOX_DOCKER_HOST`.

## Attacker capabilities

- Publish any repository content: crafted manifests, test scripts, build scripts, `conftest.py`, `build.rs`, lifecycle scripts, huge outputs, fork bombs, memory bombs, long-running processes.
- Craft archives: path traversal, absolute paths, symlinks and hard links, device files, gzip bombs, enormous file counts, invalid encodings, header tricks.
- Print anything to stdout/stderr: terminal escapes, HTML, fake log lines, fake secrets, very long lines.
- Send arbitrary HTTP requests: forged ids, other sessions' ids, cross-site requests, oversized bodies, high request rates from many IPs.
- Point UnboxAnyRepo at URLs or repositories designed to trigger SSRF through redirects or DNS.
- Attempt kernel or runtime escapes from inside the sandbox.

## Mitigations

| Threat | Mitigation | Where |
|---|---|---|
| Escaping the sandbox | gVisor (`runsc`) user-space kernel; non-root uid; all capabilities dropped; `no-new-privileges`; read-only root; no host mounts; no Docker socket; execution refuses to run without the configured runtime | `runner/docker.ts`, `runner/factory.ts` |
| Running on the host by accident | No host-execution code path exists; analysis and previews never execute repository code; runner defaults to disabled; runc requires an explicit acknowledgement and is refused in production | `runner/factory.ts`, `analysis/*`, `preview/*` |
| Trusting a sandbox that is not what it claims | The strong runtime is used only after a live probe shows a gVisor kernel **and** a verification record from `npm run sandbox -- --verify` shows every required real-container test passed for the same host, runtime and image IDs; changed images, other hosts and stale records disable execution; the record cannot be produced by configuration | `runner/verify.ts`, `runner/docker.ts`, `scripts/sandbox.ts` |
| Hostile content in analysed files | Bounded text budget; YAML parsed with alias limits (alias bombs rejected); TOML/JSON errors reported, not guessed; nothing is evaluated; regexes run per line with length caps | `analysis/*`, `source/archive.ts` |
| Scanner temp files | Only sanitized text files are written, to a fresh 0700 directory, created exclusively, with paths re-checked against the directory; scanners get a minimal environment and temporary HOME, metrics and version checks off, a timeout that kills the process group; the directory is always removed; scanner output paths outside the directory are dropped | `analysis/scanners.ts` |
| Secret exposure through results | Secret values are redacted before findings are stored; Gitleaks runs with `--redact` and its match fields are never copied; environment variable values are never read into results; reports contain the same redacted data | `analysis/rules/*`, `analysis/scanners.ts`, `report/report.ts` |
| SSRF via vulnerability lookup | OSV requests go to the fixed host `api.osv.dev` through the same guarded client (HTTPS:443, public IPs only); POSTs never follow redirects; only exact versions are sent | `analysis/osv.ts`, `github/fetcher.ts` |
| Injection through reports | Repository text is escaped for Markdown and HTML; code is fenced with a fence longer than any backtick run; only https links to known hosts become links | `report/report.ts` |
| Malicious preview pages | Served with `Content-Security-Policy: sandbox` without `allow-same-origin` (opaque origin: no cookies, storage or readable responses from the app), on a separate site (`<token>.<preview-domain>`) when configured, no cookies set or accepted, `nosniff`, unknown types as octet-stream, embeddable only by the app; the preview host serves only preview files, never the app or API; tokens are 128-bit, owned by one session, expire, and can be stopped | `preview/store.ts`, `app.ts` |
| Preview resource exhaustion | Per-preview size and file-count caps, per-session limit, global memory cap with eviction, expiry, rate limit on creation | `preview/store.ts`, `app.ts` |
| Build output tampering | Build output leaves the sandbox only through a constant `tar -c` container, size-capped, and every path is re-validated before it is served | `runner/docker.ts`, `preview/store.ts` |
| Resource exhaustion | Memory (no swap), CPU, PID, file descriptor and tmpfs workspace limits enforced by the container runtime; per-step timeouts; a watchdog over the whole run; global concurrency and queue limits | `runner/docker.ts`, `runs/manager.ts` |
| Surviving processes | Timeout and cancellation force-remove the container, which kills its entire process tree; removal is verified; a sweeper removes leftovers after crashes | `runner/docker.ts` |
| Network abuse and exfiltration | `--network none` for checks; install steps reach only an internal network whose single endpoint is the egress proxy (exact host allowlist, port 443, public IPs only) | `runner/docker.ts`, `egress-proxy/` |
| Secret theft | No secrets are passed to containers or to the Docker CLI environment; the GitHub token is sent only to `api.github.com`; logs are redacted for configured secrets and common token formats | `runner/exec.ts`, `github/client.ts`, `runs/redact.ts` |
| SSRF | Hosts are never taken from input; fixed allowlist (`api.github.com`, `codeload.github.com`); HTTPS and port 443 only; redirects re-validated per hop; DNS answers validated at connect time (any non-public address rejects) | `github/*` |
| Malicious archives | Streaming parse with size, count, per-file and decompression caps; traversal, absolute, control-character and over-long paths rejected; escaping symlinks reject the archive; in-tree symlinks are skipped; hard links and devices rejected; modes normalized; never extracted on the server | `source/*` |
| Command injection | Commands are constants in `checks/templates.ts`; processes are spawned with argv arrays and `shell: false`; the API accepts only an allowlisted check id; the only repository-derived argv values are Python requirement specifiers that pass a strict grammar | `checks/templates.ts`, `detect/requirements.ts` |
| Hostile manifests | Size-capped, parsed defensively, own-property access only, unknown formats reported as unsupported | `detect/*` |
| Install-time code execution | npm `--ignore-scripts`; pip wheels only (`--only-binary=:all:`) with config files ignored; `go mod download` and `cargo fetch` do not run project code | `checks/templates.ts` |
| XSS via logs or metadata | Logs stripped of escapes and control characters; UI inserts text with `textContent` only; strict CSP without inline scripts; `nosniff` | `runs/logs.ts`, `public/app.js`, `http/util.ts` |
| Cross-session access | 128-bit random run and inspection ids, and every read, stream, download and cancel also checks the owning session; unknown or foreign ids return 404 | `runs/manager.ts`, `runs/inspections.ts` |
| CSRF | `SameSite=Strict` HttpOnly session cookie; JSON-only bodies; `Origin` and `Sec-Fetch-Site` checks on POST | `http/util.ts` |
| Abuse and cost | Per-IP limits on inspections, runs and API calls; per-session single active run; queue limit; repository size limit before download | `app.ts`, `inspect.ts` |
| Information leaks | Generic error messages; Docker CLI errors replaced with a neutral line; stack traces only in server logs | `app.ts`, `runner/docker.ts` |
| Misleading results | UI, reports and README state that no finding and no passing check mean "safe"; every tool reports whether it ran, was not installed, failed or timed out; coverage gaps are shown; findings carry a status (confirmed, heuristic, informational, unverified); no simulated progress or scores; cancellation is reported as unconfirmed when it is | `public/*`, `analysis/index.ts`, `report/report.ts`, `runs/manager.ts` |

## Residual risks

- **Static analysis is incomplete by nature.** Pattern rules miss vulnerabilities that span files or depend on data flow, and report false positives. Dependency checks cover only exact versions and only what OSV.dev knew at the time. Gitleaks/Semgrep run only where installed.
- **Scanners parse hostile files.** Semgrep and Gitleaks are maintained tools, but a parser bug in them could be triggered by a crafted file. They run as the server's user on the server host; run them on a machine without valuable secrets, or disable them (`UNBOX_SCANNERS=off`).
- **Preview pages run in the visitor's browser.** The sandbox stops them from touching UnboxAnyRepo, but they are still arbitrary web pages: they can show misleading content, load third-party resources and track the visitor like any website. The path-based fallback URL shares the app's site (still an opaque origin).
- **The verification record is evidence of a past test run,** not a live guarantee. Host changes that do not change image IDs (kernel, gVisor version, firewall) are not detected; re-run verification after maintenance.

- **gVisor is not a VM.** A gVisor or host-kernel vulnerability could allow escape. Run the sandbox host as a dedicated, disposable VM with no credentials, no access to internal networks, and egress firewalled to the proxy's needs. Consider a microVM runner for higher assurance.
- **Install steps download third-party code.** Packages from public registries are as untrusted as the repository and run during the check step. Registries could also be used as a low-bandwidth covert channel through request paths; the sandbox holds no secrets worth leaking, but do not put private data in it.
- **The egress proxy does not inspect TLS.** It restricts destinations, not content. Registry redirects to other hosts (CDNs) need explicit allowlisting.
- **Disk usage outside the tmpfs workspace.** Container writable layers are read-only, but `/tmp` inside each container is a separate 256 MB tmpfs and Docker itself uses host disk for images.
- **Pinned SHAs from URLs** can name commits from any fork in the repository network (a GitHub property). The UI says so.
- **In-memory state and per-IP limits** are bypassable by distributed attackers and lost on restart. Put an authenticating or rate-limiting reverse proxy in front of public deployments.
- **The `docker` CLI talks to a privileged daemon.** Anyone who compromises the UnboxAnyRepo server process can control the sandbox host. Keep that process minimal and patched, and isolate the daemon on its own host.
- **Detection is best effort.** It can miss checks or offer a check that fails for environmental reasons. It never guesses commands.

## Out of scope for the MVP

Private repositories and credentials, user accounts, arbitrary commands, workflow/CI emulation, Dockerfile builds, persistent storage of results, and any form of security verdict.
