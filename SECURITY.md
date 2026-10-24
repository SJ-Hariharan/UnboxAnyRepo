# Security policy

UnboxAnyRepo reads untrusted repositories, serves previews of untrusted web pages and, on verified sandbox hosts, runs untrusted code. We take reports about its isolation and input handling seriously.

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
- cross-site scripting or CSRF in the web UI;
- a preview page reading or acting on UnboxAnyRepo's cookies, storage, API or other previews;
- secrets or environment values appearing unredacted in results, reports or logs;
- content in an analysed repository that makes the server execute it, write outside the scanner temp directory, or exhaust memory despite the limits;
- execution being enabled without a passing gVisor probe and verification record.

Out of scope:

- a repository's own tests behaving maliciously **inside** the sandbox (that is expected; tell us if it escapes);
- denial of service that only needs volume (use the documented rate limits and a reverse proxy);
- findings that require running the documented unsafe `runc` development mode;
- missed detections or false positives in the security analysis (open a normal issue; static analysis is incomplete by design);
- a previewed page behaving maliciously **within its own sandboxed origin** (that is expected).

## Deployment responsibilities

UnboxAnyRepo's guarantees depend on the deployment described in `docs/DEPLOYMENT.md`: gVisor, a dedicated sandbox host without credentials, network-layer egress rules, and pinned images. Please read `docs/THREAT_MODEL.md` for the residual risks.
