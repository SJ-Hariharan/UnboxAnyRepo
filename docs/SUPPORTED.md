# Supported projects

What UnboxAnyRepo can do for each kind of repository. "Analysis" never runs repository code. "Preview" and "Checks" are separate features with their own requirements.

## Matrix

| Project type | Detected from | Analysis and setup guide | Live preview | Sandbox checks (need a verified gVisor sandbox) |
|---|---|---|---|---|
| Static HTML/CSS/JS | `index.html` at the root (or `docs/`, `public/`, `site/` without `package.json`), no module script that needs bundling | Yes: serve command | **Yes**, served from the snapshot | — |
| Committed build output | `dist/`, `build/` or `out/` with an `index.html` | Yes | **Yes**, as committed (may be older than the source) | — |
| Vite (incl. SvelteKit) | `vite` / `@sveltejs/kit` in `package.json` | Yes: install, dev, build, preview; port from scripts/config | After a sandboxed `npm run build` (output dir from `vite.config` or `dist/`) | `npm test`, `npm run build`, `npm run lint` |
| Create React App | `react-scripts` | Yes | After a sandboxed `npm run build` (`build/`) | as above |
| Other JS front-ends (Vue, Angular, Astro, Svelte, React…) | framework packages | Yes | After a sandboxed `npm run build` (`dist/`, unverified per framework) | as above |
| Next.js | `next` | Yes | Only with `output: "export"` (`out/`); server features are not previewable | as above |
| Node.js servers (Express, Fastify, Koa, NestJS, hapi, Hono) | dependencies or a `start` script running a file | Yes: env, services, ports | **No** (needs a running server) | as above |
| Node.js libraries and tools | `package.json` | Yes | No | as above |
| Python web (Flask, Django, FastAPI, Starlette, Streamlit, Gradio, Dash…) | requirements, `pyproject.toml`, `Pipfile`, `manage.py` | Yes: venv, install, run command for the framework | **No** (needs a running server) | `pytest` / `unittest` |
| Python apps and libraries | as above | Yes | No | `pytest` / `unittest` |
| Go modules | `go.mod` | Yes | No | `go test`, `go vet`, `go build` |
| Rust crates | `Cargo.toml` | Yes | No | `cargo test`, `cargo build` |
| Dockerfile | `Dockerfile` / `Containerfile` | Yes: build and run commands, base images, exposed ports, user | No (Dockerfiles are never built by UnboxAnyRepo) | — |
| Docker Compose | `compose.yaml` / `docker-compose.yml` | Yes: services, ports, backing databases | No | — |
| Java, Ruby, PHP, .NET, Elixir, Swift, Dart… | build files | Stack, structure, secrets, CI/Docker findings | No | — |

## Package managers

| Ecosystem | Recognised | Exact versions for vulnerability lookup |
|---|---|---|
| npm | npm, Yarn (v1 and Berry), pnpm, Bun | `package-lock.json`/`npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`; exact pins in `package.json` when there is no lockfile |
| Python | pip, Poetry, uv, Pipenv | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `==` pins in requirements or `pyproject.toml` |
| Go | modules | `go.mod` require versions |
| Rust | Cargo | `Cargo.lock` |
| Others | Bundler, Composer, Maven, Gradle (listed only) | not checked |

Version ranges are never guessed: if the installed version cannot be known without resolving dependencies, it is listed as not checked.

## Analysis features

| Feature | How | Limits |
|---|---|---|
| Structure, languages, entry points | file list and extensions; `package.json` fields; conventional file names | root-level focus; monorepos partially |
| Stack and frameworks | manifests | only listed frameworks are named |
| Scripts | npm scripts, Makefile targets, Procfile, `[project.scripts]` | listed, never run |
| Docker, Compose, CI | parsed (YAML with alias limits) | GitHub Actions in depth; other CI providers listed |
| Environment variables | example env files, Compose, Dockerfiles, `process.env`/`os.environ`/`os.Getenv`/… in code | names only, values are never read into results |
| Tests | config files, test file names, frameworks | |
| Compatibility | runtime versions, lockfile conflicts, native modules, submodules, LFS, services, OS-specific scripts | heuristics |
| Security | built-in rules, OSV.dev, Semgrep and Gitleaks if installed, GitHub repository advisories | see [THREAT_MODEL.md](THREAT_MODEL.md) and the report's limitations |

## What is never done

- Running README instructions, Makefiles, Dockerfiles, CI workflows or install scripts during analysis or preview.
- Installing dependencies outside the sandbox.
- Previewing server applications (that would need a long-running process with network access).
- Testing whether a detected secret works.
