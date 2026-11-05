# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may change the HTTP API and configuration.

## [Unreleased]

### Added

- Dependency vulnerability lookup for **Ruby** (`Gemfile.lock`), **PHP** (`composer.lock`), **.NET** (`packages.lock.json`), **Dart/Flutter** (`pubspec.lock`) and **Bun** (`bun.lock`). Each was checked against the live OSV.dev API.
- Lockfiles in **subdirectories** (monorepos) are read, up to 40. Lockfiles in test fixtures are counted but not checked.
- **Git submodules** are listed from `.gitmodules`, with findings for `ext::` transports, URLs starting with `-` (CVE-2017-1000117), local paths, and unencrypted `http://`/`git://` URLs.
- **Git LFS pointer files** are found, even with binary extensions, and reported with the size of the content they stand for.
- `AUTHORS.md`.

### Fixed

- Mobile header: the sandbox status badge could push the page wider than the screen with wider fonts, as on GitHub's Ubuntu runners.
- Browser tests: a failed test no longer leaves a scripted run hanging, which had stalled CI until it timed out.
- A repository with only `bun.lock` was reported as having no npm lockfile.
- npm workspace members listed in `package-lock.json` are no longer treated as downloaded packages.

### Changed

- Copyright and package author: Hariharan ([@SJ-Hariharan](https://github.com/SJ-Hariharan)) and the UnboxAnyRepo contributors.

## [0.2.0] - 2026-10-24

First public release as **UnboxAnyRepo**.

### Added

- **Investigation without execution.** Covers stack and framework detection, project structure and entry points, package managers, and an exact-version dependency inventory:
  - npm, Yarn, pnpm and Bun
  - pip, Poetry, uv and Pipenv
  - Go and Cargo

  Also detects scripts (install lifecycle scripts highlighted), Dockerfiles, Compose services, CI workflows and environment variable *names*, with compatibility notes and a coverage report.
- **Security analysis.**
  - Built-in rules: secrets (redacted), command and SQL injection, `eval`, unsafe deserialization, path traversal, TLS, CORS, JWT and debug settings, weak password hashing, install scripts, Docker and Compose hardening, and GitHub Actions permissions, injection and pinning.
  - Dependency lookup on OSV.dev for exact versions.
  - Optional Semgrep (project-owned rules, no registry) and Gitleaks.
  - Published GitHub repository advisories.

  Every finding has a stable ID, severity, confidence, status, location, evidence, risk, remediation, method and references. Every tool reports whether it ran.
- **Setup guide** from fixed templates: installs with scripts disabled, env file, backing services, run and test commands, and ports.
- **Reports**: Markdown and JSON downloads (schema `unboxanyrepo.report/v1`).
- **Live static previews**, each on its own opaque-origin site (`<token>.preview.localhost` locally), with expiry, stop and restart, and memory limits. Build previews collect output from a verified sandbox.
- **Sandbox verification gate.** gVisor execution needs a live gVisor kernel probe and a recorded passing run of the real-container tests for the same Docker host and images. `npm run sandbox` reports PASS, FAIL, BLOCKED, NOT RUN or UNKNOWN.
- New real-container tests: host isolation, network, metadata and private-range denial, failure cleanup, crash sweep, missing images, concurrent workspaces, and egress proxy.
- A dashboard UI with section navigation, filters and accessible controls.
- Inspection-only deployment: `render.yaml` (free plan) and a `Dockerfile`.
- Documentation: [HTTP API reference](docs/API.md), [supported projects](docs/SUPPORTED.md), and this changelog.
- MIT `LICENSE`.

### Changed

- Renamed from RepoRadar to UnboxAnyRepo. Configuration variables changed from `REPORADAR_*` to `UNBOX_*`.
- CI actions are pinned to commit SHAs with `persist-credentials: false`. A separate CI job runs the real Semgrep and Gitleaks binaries, with checksums verified.

### Security

- Outbound requests go only to `api.github.com`, `codeload.github.com` and `api.osv.dev`, at public IP addresses, with each redirect re-validated. POST requests never follow redirects.
- YAML parsing caps aliases to stop alias bombs.
- Scanners run in a private temporary directory, and the whole process group is killed on timeout.

## [0.1.0] - 2026-10-22

Initial MVP as **RepoRadar**.

- Inspects public GitHub repositories at a pinned commit.
- Fetches with SSRF protection and sanitizes archives in memory.
- Detects ecosystems and proposes allowlisted checks.
- Runs checks in a hardened Docker container. gVisor is required for shared use; execution is disabled by default.
- Validation follow-up, same day:
  - `package-lock.json` added.
  - A port that is already in use is now reported clearly instead of crashing.
  - Validation report added in [docs/VALIDATION_REPORT.md](docs/VALIDATION_REPORT.md).

[Unreleased]: https://github.com/SJ-Hariharan/UnboxAnyRepo/compare/4ed942f...HEAD
[0.2.0]: https://github.com/SJ-Hariharan/UnboxAnyRepo/tree/4ed942f
