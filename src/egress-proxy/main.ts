/**
 * Start the registry egress proxy.
 *
 *   UNBOX_EGRESS_HOST       listen address (default 0.0.0.0 — run it on the internal fetch network only)
 *   UNBOX_EGRESS_PORT       listen port (default 3128)
 *   UNBOX_EGRESS_ALLOWLIST  comma-separated hostnames (default: npm, PyPI, Go proxy/sumdb, crates.io)
 */
import { createEgressProxy, DEFAULT_ALLOWLIST } from './proxy.ts';

const host = process.env.UNBOX_EGRESS_HOST ?? '0.0.0.0';
const port = Number(process.env.UNBOX_EGRESS_PORT ?? '3128');
const allowlist = (process.env.UNBOX_EGRESS_ALLOWLIST ?? DEFAULT_ALLOWLIST.join(','))
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error('UNBOX_EGRESS_PORT must be a port number');
  process.exit(2);
}

const server = createEgressProxy({ allowlist });
server.listen(port, host, () => {
  console.log(`egress proxy on ${host}:${port}; allowlist: ${allowlist.join(', ')}`);
});
for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => server.close(() => process.exit(0)));
