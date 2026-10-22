## What and why

## How it was tested

- [ ] `npm run check`
- [ ] `npm run test:e2e` (UI changes)
- [ ] `npm run test:docker` (runner or template changes; say which runtime)

## Security checklist

- [ ] No command is built from repository content, URLs or user input; no shell is used.
- [ ] Untrusted input added by this change is size-limited and validated, with hostile-case tests.
- [ ] Nothing new reaches the sandbox (secrets, sockets, mounts, network).
- [ ] Failure modes fail closed and do not leak internal details.
- [ ] Docs updated (README, ARCHITECTURE, THREAT_MODEL) where behaviour changed.
