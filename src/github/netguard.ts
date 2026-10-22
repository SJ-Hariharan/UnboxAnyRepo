/**
 * Destination guard for outbound connections.
 *
 * `guardedLookup` replaces DNS lookup for our HTTPS client and the egress
 * proxy: it resolves the name, refuses the connection if ANY resolved address
 * is non-public (loopback, private, link-local, metadata, CGNAT, multicast,
 * reserved, IPv4-mapped/translated IPv6…), and hands the socket only addresses
 * it has checked. Because the check happens inside the connect path there is no
 * window between "validate" and "connect" for DNS rebinding.
 *
 * This is defense in depth. Deployments must ALSO enforce egress rules at the
 * network layer (see docs/DEPLOYMENT.md).
 */
import dns from 'node:dns';
import net from 'node:net';
import type { LookupAddress } from 'node:dns';

const blocked = new net.BlockList();
// IPv4 special-purpose ranges (RFC 6890 and friends).
for (const [addr, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16], // link-local, includes cloud metadata 169.254.169.254
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  blocked.addSubnet(addr, prefix, 'ipv4');
}
// IPv6: anything outside global unicast is refused below; these carve-outs
// remove global-unicast ranges that embed IPv4 or are documentation/special.
for (const [addr, prefix] of [
  ['64:ff9b::', 96], // NAT64 (embeds IPv4)
  ['64:ff9b:1::', 48],
  ['2001::', 23], // IETF protocol assignments incl. Teredo
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4 (embeds IPv4)
] as const) {
  blocked.addSubnet(addr, prefix, 'ipv6');
}
const globalUnicastV6 = new net.BlockList();
globalUnicastV6.addSubnet('2000::', 3, 'ipv6');

/** True only for addresses that are routable on the public internet. */
export function isPublicAddress(address: string): boolean {
  const family = net.isIP(address);
  if (family === 4) return !blocked.check(address, 'ipv4');
  if (family === 6) {
    // Strip a zone id ("fe80::1%eth0") before checking; zoned addresses are link-local anyway.
    if (address.includes('%')) return false;
    if (!globalUnicastV6.check(address, 'ipv6')) return false; // ::1, ::, ::ffff:x, fc00::/7, fe80::/10, ff00::/8 …
    return !blocked.check(address, 'ipv6');
  }
  return false;
}

export class BlockedDestinationError extends Error {
  readonly code = 'EBLOCKED';
  constructor(hostname: string) {
    super(`Destination ${hostname} resolves to a non-public address`);
  }
}

type LookupFn = (
  hostname: string,
  options: dns.LookupAllOptions,
) => Promise<LookupAddress[]>;

const defaultResolve: LookupFn = (hostname, options) => dns.promises.lookup(hostname, options);

/** Resolve and validate; resolves with only public addresses or rejects. */
export async function resolvePublic(hostname: string, resolve: LookupFn = defaultResolve): Promise<LookupAddress[]> {
  const addresses = await resolve(hostname, { all: true, verbatim: true });
  if (addresses.length === 0) throw new BlockedDestinationError(hostname);
  for (const a of addresses) {
    if (!isPublicAddress(a.address)) throw new BlockedDestinationError(hostname);
  }
  return addresses;
}

type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

/**
 * Drop-in `lookup` for http/https/net/tls. Supports both the single-address
 * and `all: true` calling conventions used by Node's connection logic.
 */
export function makeGuardedLookup(resolve: LookupFn = defaultResolve) {
  return function guardedLookup(hostname: string, options: unknown, callback: LookupCallback): void {
    const opts = (typeof options === 'object' && options !== null ? options : {}) as { all?: boolean; family?: number };
    resolvePublic(hostname, resolve).then(
      (addrs) => {
        const filtered = opts.family === 4 || opts.family === 6 ? addrs.filter((a) => a.family === opts.family) : addrs;
        if (filtered.length === 0) {
          callback(Object.assign(new BlockedDestinationError(hostname), { errno: -1 }), '', 0);
          return;
        }
        if (opts.all) callback(null, filtered);
        else callback(null, (filtered[0] as LookupAddress).address, (filtered[0] as LookupAddress).family);
      },
      (err: unknown) => {
        const e = err instanceof Error ? err : new Error('lookup failed');
        callback(e as NodeJS.ErrnoException, '', 0);
      },
    );
  };
}

export const guardedLookup = makeGuardedLookup();
