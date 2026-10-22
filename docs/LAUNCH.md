# Launch checklist and plan

## Before making the repository public

- [ ] **Choose a license** and add `LICENSE` (for example MIT or Apache-2.0); update `package.json` and the README section.
- [ ] Replace the security contact placeholder in `SECURITY.md`, and enable GitHub private vulnerability reporting.
- [ ] **Commit `package-lock.json`** (generated and verified with `npm ci`; CI already uses `npm ci`).
- [ ] Pin sandbox images by digest in your deployment, and pin GitHub Actions to commit SHAs.
- [ ] Run `npm run check`, `npm run test:e2e`, and `npm run test:docker` with `REPORADAR_DOCKER_RUNTIME=runsc` on a real gVisor host.
- [ ] Deploy a demo instance with **execution disabled** (or demo mode) so visitors can explore safely.
- [ ] If you host execution for others: follow `docs/DEPLOYMENT.md` exactly (dedicated sandbox VM, firewall, gVisor, reverse-proxy rate limits), and read `docs/THREAT_MODEL.md` once more.
- [ ] Regenerate screenshots with `npm run screenshots`; keep the caption explaining they use the scripted runner.
- [ ] Set the repository description, topics, social preview image and a pinned "Roadmap" discussion.

## Repository description

> Inspect a public GitHub repo at a pinned commit and run one allowlisted check (npm test, pytest, go test, cargo test) in a disposable gVisor sandbox. Not a security scanner.

Suggested topics: `sandbox`, `gvisor`, `developer-tools`, `testing`, `docker`, `github`, `ci`, `security`, `nodejs`, `typescript`.

## Safe demo repositories

The bundled fixtures in `fixtures/demo-repos/` are small, written for this project and safe to execute. They power `npm run demo`, the browser tests and the screenshots:

| Fixture | Shows |
|---|---|
| `node-hello` | A passing `npm test` with no dependencies |
| `node-failing` | A failing test and how failure is reported |
| `node-with-deps` | A check that needs the registry proxy and a second confirmation |
| `python-hello` | `unittest` discovery |
| `go-hello` | `go test` fully offline |
| `rust-hello` | `cargo test` without dependencies |
| `makefile-only` | The "unsupported" state (Makefiles are never run) |

If you want live examples on a public instance, choose small, well-known repositories you have checked yourself, and present them as examples, not endorsements.

## Announcement draft

> **RepoRadar: run a GitHub repo's tests without cloning it**
>
> I built a small tool for a habit many of us have: cloning an unfamiliar repository just to see whether its tests pass. RepoRadar takes a public GitHub URL, pins the exact commit, detects Node/Python/Go/Rust projects, and shows a short list of predefined checks, with every command spelled out. You pick one and start it explicitly. It runs in a disposable gVisor container with no network, non-root, read-only, with memory/CPU/PID/disk limits and a hard timeout, and you watch the log live.
>
> What it is not: a security scanner. A passing check means the check passed in that sandbox at that commit, nothing more. The threat model and residual risks are in the repo.
>
> It is deliberately narrow: no arbitrary commands, no CI emulation, no private repos. Feedback on the isolation design and on which ecosystem templates to add next is very welcome.

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
