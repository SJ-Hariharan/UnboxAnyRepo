# Architecture

RepoRadar is a single Node.js process (no framework, one runtime dependency) that serves a static UI and a small JSON API, and drives a sandbox through a replaceable runner adapter.

```
 Browser ──HTTPS──▶ ┌──────────────────────────── RepoRadar server (trusted) ───────────────────────────┐
  (untrusted input)  │                                                                                   │
                     │  http/            sessions, CSRF checks, strict JSON bodies, rate limits, SSE     │
                     │  inspect.ts       URL ─▶ metadata ─▶ pinned SHA ─▶ archive ─▶ snapshot ─▶ detect  │
                     │  github/          url.ts · fetcher.ts · netguard.ts · client.ts ──────────────────┼──▶ api.github.com
                     │  source/          tar.ts · archive.ts  (parse + sanitize in memory, never on disk)│    codeload.github.com
                     │  detect/          node · python · go · rust  (pure functions over manifests)      │    (fixed hosts only)
                     │  checks/          templates.ts  ◀── the ONLY place commands are defined           │
                     │  runs/            manager (queue, quotas, watchdog), logs (sanitize, redact, cap) │
                     │  runner/          Runner interface ─┬─ DisabledRunner (default, fails closed)     │
                     │                                     └─ DockerRunner (gVisor runsc)               │
                     └──────────────────────────────────────────────┬────────────────────────────────────┘
                                                                    │ docker CLI (argv only, minimal env)
                                                                    ▼
                     ┌───────────────────── Sandbox host (dedicated, holds no app secrets) ──────────────┐
                     │  per run: tmpfs volume (size-capped)  +  keeper / prepare / step containers       │
                     │  every container: runsc, uid 65532, cap-drop ALL, no-new-privileges, read-only    │
                     │  rootfs, memory/CPU/PID/fd limits, no host mounts, no docker socket               │
                     │  check steps:   --network none                                                    │
                     │  install steps: internal "fetch" network ──▶ egress proxy ──▶ allowlisted         │
                     │                                            (CONNECT :443 only)  package registries│
                     └───────────────────────────────────────────────────────────────────────────────────┘
```

## Modules and responsibilities

| Area | Files | Responsibility |
|---|---|---|
| Config | `src/config.ts` | Parse and validate every environment variable once. Invalid config stops startup. |
| Web/API | `src/app.ts`, `src/http/*` | Routing, sessions, CSRF, body limits, rate limits, SSE, security headers, static assets. |
| GitHub | `src/github/*` | Parse repo URLs; fetch metadata and pin a commit; download the archive with size/time limits. |
| Source | `src/source/*` | Streaming tar reader/writer; sanitize the archive into a clean tar.gz rooted at `src/`. |
| Detection | `src/detect/*` | Read a few small root manifests (as hostile input) and produce typed facts. |
| Checks | `src/checks/*` | Turn facts into allowlisted check plans with constant argv arrays. |
| Runs | `src/runs/*` | Run lifecycle, queue, per-session ownership, cancellation, watchdog, retention, logs. |
| Runner | `src/runner/*` | Execute a plan in a sandbox. Replaceable: the UI and API only see the `Runner` interface. |
| Egress proxy | `src/egress-proxy/*` | Optional CONNECT proxy that lets install steps reach package registries only. |
| Demo | `src/demo/*`, `fixtures/demo-repos/*` | Offline GitHub stand-in serving bundled, safe fixtures. |
| UI | `public/*` | Static HTML/CSS and one plain JS module; all untrusted text is inserted with `textContent`. |

## Request flow

1. **Inspect** (`POST /api/inspect {url}`): parse URL → `GET /repos/{owner}/{repo}` (must be public) → resolve the default branch head (or verify a SHA from the URL) → download `codeload.github.com/{owner}/{repo}/tar.gz/{sha}` → sanitize in memory → detect → store the inspection (session-bound, 15 min default) → return metadata, the pinned SHA, detection results and the exact plan of every check.
2. **Run** (`POST /api/runs {inspectionId, checkId, acknowledged: true}`): the server re-derives the plan from its own stored detection; the client only names an allowlisted check id. Quotas and runner availability are checked, then the run is queued.
3. **Execute**: the runner creates a size-capped tmpfs volume, streams the sanitized source into it from inside the sandbox, then runs each step in a fresh container. On success, failure, timeout or cancellation every container and the volume are force-removed, and removal is verified.
4. **Observe** (`GET /api/runs/:id/events`, SSE): state changes and log lines in batches; the final retained log replaces the live view at the end. The UI falls back to polling if the stream drops.

## Runner adapter contract

```ts
interface Runner {
  status(force?: boolean): Promise<RunnerStatus>; // available? isolation? per-ecosystem images? dependency fetch?
  execute(req: ExecuteRequest): Promise<ExecuteResult>; // succeeded | failed | timed_out | cancelled | unavailable
  sweep?(): Promise<void>; // remove leftovers, never touching in-flight runs
}
```

A new adapter (Firecracker microVMs, a hosted sandbox API, Kubernetes with gVisor/Kata) needs only these three methods. It must fail closed: report `available: false` with a user-safe reason rather than degrading isolation.

## State and retention

All state is in memory in one process:

- inspections, including the sanitized source archive: 15 minutes, evicted earlier under memory pressure (512 MB cap);
- runs and their retained logs (first 256 KB plus last 64 KB): 1 hour after they finish;
- nothing is written to disk by the server. A restart forgets everything.

Because state is in memory, run exactly one server process per deployment (see [DEPLOYMENT.md](DEPLOYMENT.md)).

## Why these choices

- **No framework, one runtime dependency (`smol-toml`).** The attack surface of the trusted side stays small and auditable; Node's built-in type stripping runs the TypeScript directly, so there is no build step.
- **Own tar reader.** Archive handling is a core security boundary; a small, strict, fully tested parser that never touches the filesystem is easier to reason about than a general extractor.
- **Docker + gVisor first.** It is widely available, works on a single VM, and gVisor's user-space kernel is a materially stronger boundary than plain containers. The adapter interface leaves room for microVMs.
