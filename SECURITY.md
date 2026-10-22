# Security policy

RepoRadar runs untrusted code by design, so we take reports about its isolation and input handling seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Instead, report privately:

- Email: `SECURITY-CONTACT@EXAMPLE.COM` *(placeholder: maintainers must replace this before launch)*
- or use GitHub's private vulnerability reporting for this repository, once it is enabled.

Include what you found, how to reproduce it, the configuration you used (runner, runtime, limits), and the impact you believe it has. We aim to acknowledge reports within a few working days and will keep you informed while we work on a fix. We are happy to credit reporters who want to be credited.

## Scope

In scope:

- escaping the sandbox, or affecting the sandbox host or other runs;
- reaching networks, hosts or metadata endpoints that the design says are unreachable;
- reading, streaming or cancelling another session's runs or inspections;
- SSRF through GitHub URL handling or redirects;
- archive handling that writes, reads or reveals anything outside the intended snapshot;
- executing commands other than the allowlisted templates, or bypassing the confirmation step;
- leaking secrets, host paths or infrastructure details through the API or logs;
- cross-site scripting or CSRF in the web UI.

Out of scope:

- a repository's own tests behaving maliciously **inside** the sandbox (that is expected; tell us if it escapes);
- denial of service that only needs volume (use the documented rate limits and a reverse proxy);
- findings that require running the documented unsafe `runc` development mode.

## Deployment responsibilities

RepoRadar's guarantees depend on the deployment described in `docs/DEPLOYMENT.md`: gVisor, a dedicated sandbox host without credentials, network-layer egress rules, and pinned images. Please read `docs/THREAT_MODEL.md` for the residual risks.
