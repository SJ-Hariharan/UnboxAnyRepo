# Deployment

RepoRadar has two parts: the **web server** (this Node.js process) and the **sandbox host** (a Docker daemon with gVisor). They can be the same machine for a small private deployment, but the recommended layout separates them.

## Supported configurations

| Configuration | Execution | Use it for |
|---|---|---|
| `REPORADAR_RUNNER=disabled` (default) | Off. Inspection and plan review only. | Public demos, evaluation, any host without gVisor. |
| `REPORADAR_RUNNER=docker`, `REPORADAR_DOCKER_RUNTIME=runsc` | gVisor sandbox. | The only supported configuration for running untrusted code for other people. |
| `REPORADAR_RUNNER=docker`, `REPORADAR_DOCKER_RUNTIME=runc`, plus `REPORADAR_ALLOW_UNSAFE_LOCAL_RUNNER=i-understand-runc-is-not-a-strong-sandbox` | Plain containers. Labelled unsafe in the UI and logs; refused when `NODE_ENV=production`. | Local development on a throwaway VM only. |

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
     ┌─────────▼─────────┐   REPORADAR_DOCKER_HOST ─────────▶│  no app secrets, no cloud     │
     │ RepoRadar server  │                                   │  credentials, no internal     │
     │ (one process)     │                                   │  network access               │
     └───────────────────┘                                   └──────────────────────────────┘
```

- The sandbox VM should hold **no credentials** (no cloud instance role, no SSH keys to other systems) and should be **firewalled** so that only the egress proxy can reach the internet, and nothing can reach your internal networks or the cloud metadata endpoint. These network-layer rules are required in addition to RepoRadar's own checks.
- Treat the sandbox VM as disposable. Rebuild it from an image regularly.
- Access to the Docker API is root-equivalent on the sandbox VM. Protect the SSH key or TLS client certificate used by `REPORADAR_DOCKER_HOST` like any production secret.

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
   export REPORADAR_IMAGE_NODE=node:24-bookworm-slim   # or name:tag@sha256:…
   node scripts/pull-images.ts
   ```
4. **Optional: enable dependency downloads.** Without this, checks that need to install packages are shown but disabled.
   ```sh
   docker compose -f deploy/compose.sandbox-host.yml up -d
   ```
   This creates an `internal` Docker network named `reporadar-fetch` and an egress proxy reachable on it as `reporadar-egress:3128`. RepoRadar verifies that the network is internal before using it. If a registry redirects downloads to another host, add that host to `REPORADAR_EGRESS_ALLOWLIST`.

## Web server setup

```sh
npm ci            # or npm install on first setup, then commit package-lock.json
NODE_ENV=production \
REPORADAR_RUNNER=docker \
REPORADAR_DOCKER_RUNTIME=runsc \
REPORADAR_DOCKER_HOST=ssh://sandbox@sandbox-vm.internal \
REPORADAR_FETCH_NETWORK=reporadar-fetch \
REPORADAR_FETCH_PROXY_URL=http://reporadar-egress:3128 \
REPORADAR_PUBLIC_ORIGIN=https://reporadar.example.com \
REPORADAR_TRUST_PROXY=true \
HOST=127.0.0.1 PORT=8787 \
node src/server.ts
```

Or put the variables in a file and run `node --env-file=.env src/server.ts`. See [`.env.example`](../.env.example) for every option.

Run it under a process manager (systemd, a container platform) as an unprivileged user. Run **exactly one** instance: runs, sessions and rate limits are held in memory.

Behind a reverse proxy, terminate TLS there, set `REPORADAR_PUBLIC_ORIGIN`, and set `REPORADAR_TRUST_PROXY=true` only if exactly one trusted proxy appends to `X-Forwarded-For`. Disable response buffering for `/api/runs/*/events` (RepoRadar sends `X-Accel-Buffering: no` for nginx).

`GET /healthz` returns `{"ok":true}` for liveness checks.

## Resource planning

Per concurrent run, budget roughly the configured memory limit (default 2 GB) plus the tmpfs workspace actually used (up to 2 GB by default, held in RAM) plus one CPU. With the defaults, `REPORADAR_MAX_CONCURRENT_RUNS=2` needs about 8 GB of RAM and 2 vCPUs on the sandbox host in the worst case. Rust and large TypeScript builds are the heaviest workloads; lower concurrency or raise limits accordingly.

The web server itself is light (about 100 MB plus held inspection archives, capped at 512 MB).

## Rate limits and abuse

Defaults per client IP: 30 inspections per 10 minutes, 6 runs per hour, 300 API requests per minute; one active run per browser session; 2 concurrent runs and 8 queued runs overall. These are in-memory and per process. For a public service also add limits at the reverse proxy, and consider requiring sign-in in front of the run endpoint. GitHub's unauthenticated API limit is 60 requests per hour per server IP; set `GITHUB_TOKEN` (a token with no scopes is enough for public data) for higher limits.

## Retention

Inspections, including the source archive, are kept in memory for 15 minutes; finished runs and their capped logs for 1 hour. Nothing is written to disk by the server. Sandbox volumes are tmpfs and are deleted at the end of each run. Server logs contain request errors and egress-proxy decisions; set your own retention for them.

## Upgrades

Pin images by digest and update them deliberately. After changing images or runtime configuration, check the header status in the UI or the startup log: it states which runner is active and why execution is disabled if it is.
