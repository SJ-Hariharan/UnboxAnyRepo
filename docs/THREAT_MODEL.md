# Threat model

RepoRadar's central feature is executing code from arbitrary public repositories. This document assumes that every repository is malicious and that some users are abusive.

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
5. **Server → Docker daemon.** Whoever controls the Docker API controls the sandbox host, so the server and the sandbox host must be operated as one trust domain, or the daemon placed on a dedicated host reached with `REPORADAR_DOCKER_HOST`.

## Attacker capabilities

- Publish any repository content: crafted manifests, test scripts, build scripts, `conftest.py`, `build.rs`, lifecycle scripts, huge outputs, fork bombs, memory bombs, long-running processes.
- Craft archives: path traversal, absolute paths, symlinks and hard links, device files, gzip bombs, enormous file counts, invalid encodings, header tricks.
- Print anything to stdout/stderr: terminal escapes, HTML, fake log lines, fake secrets, very long lines.
- Send arbitrary HTTP requests: forged ids, other sessions' ids, cross-site requests, oversized bodies, high request rates from many IPs.
- Point RepoRadar at URLs or repositories designed to trigger SSRF through redirects or DNS.
- Attempt kernel or runtime escapes from inside the sandbox.

## Mitigations

| Threat | Mitigation | Where |
|---|---|---|
| Escaping the sandbox | gVisor (`runsc`) user-space kernel; non-root uid; all capabilities dropped; `no-new-privileges`; read-only root; no host mounts; no Docker socket; execution refuses to run without the configured runtime | `runner/docker.ts`, `runner/factory.ts` |
| Running on the host by accident | No host-execution code path exists; runner defaults to disabled; runc requires an explicit acknowledgement and is refused in production | `runner/factory.ts` |
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
| Misleading results | UI and README state that a pass is not a safety verdict; no simulated progress; cancellation is reported as unconfirmed when it is | `public/*`, `runs/manager.ts` |

## Residual risks

- **gVisor is not a VM.** A gVisor or host-kernel vulnerability could allow escape. Run the sandbox host as a dedicated, disposable VM with no credentials, no access to internal networks, and egress firewalled to the proxy's needs. Consider a microVM runner for higher assurance.
- **Install steps download third-party code.** Packages from public registries are as untrusted as the repository and run during the check step. Registries could also be used as a low-bandwidth covert channel through request paths; the sandbox holds no secrets worth leaking, but do not put private data in it.
- **The egress proxy does not inspect TLS.** It restricts destinations, not content. Registry redirects to other hosts (CDNs) need explicit allowlisting.
- **Disk usage outside the tmpfs workspace.** Container writable layers are read-only, but `/tmp` inside each container is a separate 256 MB tmpfs and Docker itself uses host disk for images.
- **Pinned SHAs from URLs** can name commits from any fork in the repository network (a GitHub property). The UI says so.
- **In-memory state and per-IP limits** are bypassable by distributed attackers and lost on restart. Put an authenticating or rate-limiting reverse proxy in front of public deployments.
- **The `docker` CLI talks to a privileged daemon.** Anyone who compromises the RepoRadar server process can control the sandbox host. Keep that process minimal and patched, and isolate the daemon on its own host.
- **Detection is best effort.** It can miss checks or offer a check that fails for environmental reasons. It never guesses commands.

## Out of scope for the MVP

Private repositories and credentials, user accounts, arbitrary commands, workflow/CI emulation, Dockerfile builds, persistent storage of results, and any form of security verdict.
