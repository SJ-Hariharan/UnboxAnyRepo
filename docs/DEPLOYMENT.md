# Deployment

UnboxAnyRepo has two parts: the **web server** (this Node.js process: inspection, analysis, reports, static previews) and, optionally, the **sandbox host** (a Docker daemon with gVisor) for running checks and build previews. Most deployments only need the web server: everything except running code works without a sandbox.

## Zero-cost, inspection-only deployment

This is the recommended way to publish UnboxAnyRepo for others. Execution stays disabled: there is no Docker, no sandbox and no verification record on the web service, so it cannot run repository code even if someone sets `UNBOX_RUNNER=docker`.

**Render (free web service)** — `render.yaml` in the repository is a Blueprint for this:

1. Push the repository to GitHub, then in Render choose *New → Blueprint* and select it. Review every value before applying.
2. Add a `GITHUB_TOKEN` secret: a fine-grained token with **no permissions** (public data only). Without it the service shares GitHub's 60-requests-per-hour anonymous limit with every other app on the same outbound IP and will hit it quickly.
3. After the first deploy, set `UNBOX_PUBLIC_ORIGIN` to the service URL (for example `https://<name>.onrender.com`) and redeploy.
4. Check `https://<name>.onrender.com/healthz` returns `{"ok":true}`, then inspect a small repository.

Free-plan constraints at the time of writing (check [render.com/pricing](https://render.com/pricing) before relying on them): the service sleeps after about 15 minutes without traffic and the next request waits for a cold start; memory is about 512 MB and CPU is a fraction of a core; free instance hours per month are limited; the filesystem is ephemeral (UnboxAnyRepo keeps nothing on disk anyway). `render.yaml` lowers archive, analysis and preview limits to fit, runs two inspections at a time, turns external scanners off (they are not installed there) and uses path-based previews (no wildcard DNS on the free plan). Reports say which checks did not run.

`UNBOX_TRUST_PROXY=true` assumes Render's proxy appends the client address to `X-Forwarded-For` as the last entry. This was not verified against a live deployment; if per-IP rate limits behave oddly, set it to `false` (all visitors then share one limit).

**Any container host** — the `Dockerfile` builds an inspection-only image (no Docker CLI, no socket, runs as the `node` user, health check on `/healthz`). Set the same environment variables as in `render.yaml`. Hosts that offer free tiers change their terms often; this repository does not assume any particular one.

**Public deployment has not been tested by the maintainers.** The configuration was validated locally only.

## Previews in production

Static previews are always served with a `Content-Security-Policy: sandbox` header (opaque origin). For stronger isolation, and so that pages using absolute paths (`/assets/app.js`) work, serve previews on their own site:

1. Pick a domain that is **not** a subdomain of the app's cookie scope, for example `preview-example.net` or `preview.example.com` when the app is on `app.example.org`.
2. Create wildcard DNS `*.preview.example.com` pointing to the server and a wildcard TLS certificate at the proxy.
3. Set `UNBOX_PREVIEW_DOMAIN=preview.example.com` and `UNBOX_PUBLIC_ORIGIN=https://app.example.org`.

Without a preview domain (`UNBOX_PREVIEW_DOMAIN=off`), previews use `/preview/<token>/` on the app's own host; pages with absolute asset paths may render incompletely.

## Supported configurations

| Configuration | Execution | Use it for |
|---|---|---|
| `UNBOX_RUNNER=disabled` (default) | Off. Inspection and plan review only. | Public demos, evaluation, any host without gVisor. |
| `UNBOX_RUNNER=docker`, `UNBOX_DOCKER_RUNTIME=runsc`, plus a passing `npm run sandbox -- --verify` | gVisor sandbox, enabled only after a live gVisor probe and a recorded real-container test run for the current images. | The only supported configuration for running untrusted code for other people. |
| `UNBOX_RUNNER=docker`, `UNBOX_DOCKER_RUNTIME=runc`, plus `UNBOX_ALLOW_UNSAFE_LOCAL_RUNNER=i-understand-runc-is-not-a-strong-sandbox` | Plain containers. Labelled unsafe in the UI and logs; refused when `NODE_ENV=production`. | Local development on a throwaway VM only. |

If the configured runtime is missing, images are absent or Docker is unreachable, the runner reports itself unavailable and the UI explains why. It never falls back to a weaker mode.

## Recommended layout

```
            Internet
               │
     ┌─────────▼─────────┐        ssh:// or tcp+TLS          ┌──────────────────────────────┐
     │ Reverse proxy     │                                   │ Sandbox VM (dedicated)        │
     │ TLS, rate limits  │                                   │  Docker + gVisor (runsc)      │
     └─────────┬─────────┘                                   │  sandbox images (pre-pulled)  │
               │                                             │  egress proxy + fetch network │
     ┌─────────▼─────────┐   UNBOX_DOCKER_HOST ─────────▶│  no app secrets, no cloud     │
     │ UnboxAnyRepo server  │                                   │  credentials, no internal     │
     │ (one process)     │                                   │  network access               │
     └───────────────────┘                                   └──────────────────────────────┘
```

- The sandbox VM should hold **no credentials** (no cloud instance role, no SSH keys to other systems) and should be **firewalled** so that only the egress proxy can reach the internet, and nothing can reach your internal networks or the cloud metadata endpoint. These network-layer rules are required in addition to UnboxAnyRepo's own checks.
- Treat the sandbox VM as disposable. Rebuild it from an image regularly.
- Access to the Docker API is root-equivalent on the sandbox VM. Protect the SSH key or TLS client certificate used by `UNBOX_DOCKER_HOST` like any production secret.

## Sandbox host setup

1. **Install Docker** from your distribution or Docker's packages. cgroups v2 is recommended.
2. **Install gVisor** following the [official installation guide](https://gvisor.dev/docs/user_guide/install/), then register it with Docker as described in the [Docker quick start](https://gvisor.dev/docs/user_guide/docker):
   ```sh
   sudo runsc install
   sudo systemctl restart docker
   docker run --rm --runtime=runsc hello-world
   ```
3. **Pull the sandbox images** (the runner never pulls implicitly). Pin them by digest in production:
   ```sh
   export UNBOX_IMAGE_NODE=node:24-bookworm-slim   # or name:tag@sha256:…
   node scripts/pull-images.ts
   ```
4. **Verify the sandbox.** From a checkout of UnboxAnyRepo configured like the server (same `UNBOX_DOCKER_HOST`, runtime and images):
   ```sh
   npm run sandbox               # diagnostics only: PASS / FAIL / BLOCKED / NOT RUN / UNKNOWN per item
   npm run sandbox -- --verify   # also runs the real-container tests; writes .unbox/sandbox-verification.json if all pass
   ```
   The web server reads that record (`UNBOX_SANDBOX_VERIFICATION_FILE`). Copy it to the server if they are different machines. Re-run after pulling or changing images, upgrading gVisor or Docker, or after 30 days (`UNBOX_SANDBOX_VERIFICATION_MAX_AGE_DAYS`).
5. **Optional: enable dependency downloads.** Without this, checks that need to install packages are shown but disabled.
   ```sh
   docker compose -f deploy/compose.sandbox-host.yml up -d
   ```
   This creates an `internal` Docker network named `unbox-fetch` and an egress proxy reachable on it as `unbox-egress:3128`. UnboxAnyRepo verifies that the network is internal before using it. If a registry redirects downloads to another host, add that host to `UNBOX_EGRESS_ALLOWLIST`.

## Web server setup

```sh
npm ci            # exact versions from package-lock.json
NODE_ENV=production \
UNBOX_RUNNER=docker \
UNBOX_DOCKER_RUNTIME=runsc \
UNBOX_DOCKER_HOST=ssh://sandbox@sandbox-vm.internal \
UNBOX_FETCH_NETWORK=unbox-fetch \
UNBOX_FETCH_PROXY_URL=http://unbox-egress:3128 \
UNBOX_PUBLIC_ORIGIN=https://unboxanyrepo.example.com \
UNBOX_TRUST_PROXY=true \
HOST=127.0.0.1 PORT=8787 \
node src/server.ts
```

Or put the variables in a file and run `node --env-file=.env src/server.ts`. See [`.env.example`](../.env.example) for every option.

Run it under a process manager (systemd, a container platform) as an unprivileged user. Run **exactly one** instance: runs, sessions and rate limits are held in memory.

Behind a reverse proxy, terminate TLS there, set `UNBOX_PUBLIC_ORIGIN`, and set `UNBOX_TRUST_PROXY=true` only if exactly one trusted proxy appends to `X-Forwarded-For`. Disable response buffering for `/api/runs/*/events` (UnboxAnyRepo sends `X-Accel-Buffering: no` for nginx).

`GET /healthz` returns `{"ok":true}` for liveness checks.

## Resource planning

Per concurrent run, budget roughly the configured memory limit (default 2 GB) plus the tmpfs workspace actually used (up to 2 GB by default, held in RAM) plus one CPU. With the defaults, `UNBOX_MAX_CONCURRENT_RUNS=2` needs about 8 GB of RAM and 2 vCPUs on the sandbox host in the worst case. Rust and large TypeScript builds are the heaviest workloads; lower concurrency or raise limits accordingly.

The web server itself is light (about 100 MB plus held inspection archives, capped at 512 MB).

## Rate limits and abuse

Defaults per client IP: 30 inspections per 10 minutes, 6 runs per hour, 300 API requests per minute; one active run per browser session; 2 concurrent runs and 8 queued runs overall. These are in-memory and per process. For a public service also add limits at the reverse proxy, and consider requiring sign-in in front of the run endpoint. GitHub's unauthenticated API limit is 60 requests per hour per server IP; set `GITHUB_TOKEN` (a token with no scopes is enough for public data) for higher limits.

## Retention

Inspections, including the source archive, are kept in memory for 15 minutes; finished runs and their capped logs for 1 hour. Nothing is written to disk by the server. Sandbox volumes are tmpfs and are deleted at the end of each run. Server logs contain request errors and egress-proxy decisions; set your own retention for them.

## Upgrades

Pin images by digest and update them deliberately. After changing images or runtime configuration, check the header status in the UI or the startup log: it states which runner is active and why execution is disabled if it is.
