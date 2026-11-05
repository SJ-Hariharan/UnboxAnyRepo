# HTTP API

The web UI is a thin client over this JSON API. Everything the UI can do, a script can do too, with the same limits. The API is meant for the bundled UI and for local automation; it is not versioned yet, and fields may change between minor releases (see the [changelog](../CHANGELOG.md)).

## Conventions

- **Base URL:** the server itself, for example `http://127.0.0.1:8787`.
- **Session:** the first `/api/` request sets an HTTP-only `uar_sid` cookie (`SameSite=Strict`, `Secure` in production). Inspections, runs and previews belong to the session that created them. Other sessions get `404`. Keep the cookie between calls (`curl -c jar -b jar`).
- **Methods:** only `GET` and `POST`. Anything else returns `405`.
- **Request bodies:** `POST` bodies must be JSON objects with `Content-Type: application/json`, up to 8 KB. Unknown fields are rejected with `unexpected_field`.
- **Cross-site protection:** a `POST` with `Sec-Fetch-Site: cross-site` is refused (`cross_site`). So is one whose `Origin` is not the server's own origin, or `UNBOX_PUBLIC_ORIGIN` when that is set (`bad_origin`). Requests without an `Origin` header, such as `curl`, are allowed.
- **IDs:** inspection and run IDs are opaque strings. Preview tokens are 32 lowercase hex characters.
- **Errors:** every error has the same shape:

  ```json
  { "error": { "code": "inspection_expired", "message": "That inspection has expired. Inspect the repository again.", "retryAfterSec": 30 } }
  ```

  `retryAfterSec` and the `Retry-After` header are present only when waiting helps, for example after `429`. Unexpected failures return `500 internal` with a generic message. Details go to the server log, never to the client.

## Rate limits (per client IP)

| Scope | Limit |
|---|---|
| Any `/api/` request | 300 per minute |
| `POST /api/inspect` | `UNBOX_INSPECTIONS_PER_IP_PER_10_MIN` (default 30) per 10 minutes, and at most `UNBOX_MAX_CONCURRENT_INSPECTIONS` server-wide |
| `POST /api/runs` | `UNBOX_RUNS_PER_IP_PER_HOUR` (default 6) per hour, counted only for runs that are created |
| `POST /api/previews` | 20 per 10 minutes |
| `GET /api/runs/:id/events` | 4 open streams per session |

Behind a reverse proxy, the client IP comes from `X-Forwarded-For` only when `UNBOX_TRUST_PROXY=true`.

## Endpoints

### `GET /healthz`

Liveness check. Returns `{ "ok": true }`. Sets no session.

### `GET /api/config`

Describes this deployment: product name and version, the enabled features (`previews`, `osv`, `githubAdvisories`, `scanners`), whether it runs in demo mode, and example repositories. It also includes the supported ecosystems, the runner state with the reason execution is unavailable, and the public limits. The runner block never contains host paths or secrets.

### `POST /api/inspect`

Fetches and analyses one public GitHub repository at a pinned commit. No repository code is run.

```json
{ "url": "https://github.com/owner/repo" }
```

`url` must be a `https://github.com/<owner>/<repo>` URL. The response describes the inspection:

| Field | Description |
|---|---|
| `id` | Inspection ID |
| `repo` | Repository identity |
| `commit` | `sha` and how it was resolved |
| `source` | Archive size and file counts |
| `detection` | Ecosystems, warnings and unsupported signals |
| `checks` | Available checks, each with its steps, repository scripts it would run, and `blockedReason` if it cannot start |
| `analysis` | Stack, structure, dependencies, configuration, environment variable names, Git submodules and LFS pointers (`git`), launch plan, preview eligibility, findings, tool states and coverage |

Inspections expire after `UNBOX_INSPECTION_RETENTION_SEC` (default 15 minutes).

Common errors:

| Status | Codes | Meaning |
|---|---|---|
| `400` | `invalid_url` | The URL is not a GitHub repository URL |
| `404` | `github_not_found`, `github_not_public` | The repository is missing or private |
| `413` | `too_large`, `github_too_large`, `source_too_large` | The repository or archive is over the limits |
| `422` | `unsafe_source` | The archive was rejected by the sanitizer (traversal, links, devices, bombs) |
| `429` | `rate_limited`, `github_rate_limited` | Too many requests from this client, or GitHub's own API limit |
| `503` | `busy` | Too many inspections are running |
| `502`, `504` | `github_network`, `github_upstream`, `github_timeout` | GitHub or the network failed |

A `/tree/<sha>` or `/commit/<sha>` URL with a full 40-character SHA pins that commit. Other paths fall back to the default branch, and `notice` says so.

### `GET /api/inspections/:id/report?format=md|json`

Downloads the full report as an attachment. `md` (default) is Markdown, with repository-supplied text escaped. `json` follows schema `unboxanyrepo.report/v1`. Secret values are always redacted. Returns `404 inspection_expired` once the inspection is gone.

### `POST /api/previews`

Starts a **static** preview of an inspected repository, served from the sanitized snapshot. Nothing is built or executed.

```json
{ "inspectionId": "…" }
```

Returns `201` with `{ "preview": { "token", "url", "pathUrl", "state", "kind", "files", "bytes", "expiresAt", "health", … } }`:

- `url` is the preview's own site (`http://<token>.preview.localhost:<port>/` locally, or `<token>.<UNBOX_PREVIEW_DOMAIN>`).
- `pathUrl` is the `/preview/<token>/` fallback.

Errors:

| Status | Code | Meaning |
|---|---|---|
| `409` | `previews_disabled` | Previews are turned off on this deployment |
| `409` | `preview_not_supported` | The project needs a build, or is a server app; the message says which |
| `413` | `too_large` | The files are too large to preview |

### `GET /api/previews`

Lists this session's previews.

### `POST /api/previews/:token/stop` · `POST /api/previews/:token/restart`

Stops a preview, or restarts a stopped or expired one from the same snapshot. Both return `{ "preview": … }`. A token from another session returns `404`.

### Preview pages

`GET /preview/<token>/<path>` and `GET http://<token>.<preview-domain>/<path>` serve the files of a running preview. Every response carries `Content-Security-Policy: sandbox` without `allow-same-origin`, so the page runs in an opaque origin and cannot use the app's cookies, storage or API. Preview hosts serve only preview files, never the UI or the API.

### `POST /api/runs`

Starts an allowlisted check (tests, build, lint) in the sandbox. This works **only** when execution is enabled and verified (see [DEPLOYMENT.md](DEPLOYMENT.md)); otherwise it returns `503 execution_unavailable`.

```json
{ "inspectionId": "…", "checkId": "node:test", "acknowledged": true, "preview": false }
```

| Field | Description |
|---|---|
| `checkId` | Must be one of the inspection's `checks[].id`. Commands are never accepted from the client. |
| `acknowledged` | Must be `true` (otherwise `400 ack_required`). It confirms the user understands repository code will run in the sandbox. |
| `preview` | Set to `true` on a project's build check to collect the build output as a preview. |

Other errors:

- `400 unknown_check`: the check ID is not one of the inspection's checks.
- `409`: `check_unavailable`, `ecosystem_unavailable` or `dependency_fetch_unavailable`.
- `429 session_busy`: this session already has a run in progress.
- `503 queue_full`: the sandbox queue is full.

Returns `201 { "run": … }`. Run states are:

- In progress: `queued`, `preparing`, `installing`, `running`.
- Final: `succeeded`, `failed`, `timed_out`, `cancelled`, `unavailable`.

### `GET /api/runs` · `GET /api/runs/:id`

Lists this session's runs, or gets one run with its log lines so far.

### `GET /api/runs/:id/events`

A Server-Sent Events stream. It sends these events:

| Event | Payload | When |
|---|---|---|
| `state` | `{ run }` | State changes |
| `log` | `{ lines: [{ seq, kind, text }] }` | Batches of log lines; the event `id` is the last line's `seq` |
| `truncated` | | The log hit its size cap and middle lines were dropped |
| `end` | `{ run }` | Final state; the stream then closes |

Resume with the `Last-Event-ID` header or `?after=<seq>`. A comment line is sent every 15 seconds as a keep-alive. Log text is sanitized and secrets are redacted before storage.

### `GET /api/runs/:id/log`

Downloads the full (capped) run log as a text attachment.

### `POST /api/runs/:id/cancel`

Cancels a run. The containers are stopped and removed. Returns `202 { "run": … }`.

## Example

```sh
curl -s -c jar -b jar -H 'Content-Type: application/json' \
  -d '{"url":"https://github.com/SJ-Hariharan/UnboxAnyRepo"}' \
  http://127.0.0.1:8787/api/inspect > inspection.json
ID=$(node -p 'require("./inspection.json").id')
curl -s -b jar -OJ "http://127.0.0.1:8787/api/inspections/$ID/report?format=md"
```
