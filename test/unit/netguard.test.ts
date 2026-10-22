import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPublicAddress, resolvePublic, makeGuardedLookup, BlockedDestinationError } from '../../src/github/netguard.ts';

test('classifies non-public IPv4 and IPv6 addresses as blocked', () => {
  const blocked = [
    '0.0.0.0', '10.1.2.3', '100.64.0.1', '127.0.0.1', '127.255.255.254', '169.254.169.254', '172.16.0.1',
    '172.31.255.255', '192.0.0.8', '192.0.2.5', '192.168.1.1', '198.18.0.1', '198.51.100.7', '203.0.113.9',
    '224.0.0.1', '239.255.255.250', '240.0.0.1', '255.255.255.255',
    '::', '::1', '::ffff:127.0.0.1', '::ffff:169.254.169.254', '::ffff:7f00:1', 'fc00::1', 'fd12:3456::1',
    'fe80::1', 'fe80::1%eth0', 'ff02::1', '64:ff9b::7f00:1', '2002:7f00:1::1', '2001:db8::1', '2001::1',
    'fec0::1', 'not-an-ip', '',
  ];
  for (const a of blocked) assert.equal(isPublicAddress(a), false, a);
});

test('allows ordinary public addresses', () => {
  for (const a of ['140.82.112.3', '185.199.108.133', '8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '2a00:1450:4001::200e']) {
    assert.equal(isPublicAddress(a), true, a);
  }
});

test('resolvePublic rejects when any resolved address is private (rebinding defense)', async () => {
  const mixed = async () => [
    { address: '140.82.112.3', family: 4 },
    { address: '10.0.0.5', family: 4 },
  ];
  await assert.rejects(resolvePublic('api.github.com', mixed), BlockedDestinationError);
  await assert.rejects(resolvePublic('x', async () => []), BlockedDestinationError);
  const ok = await resolvePublic('api.github.com', async () => [{ address: '140.82.112.3', family: 4 }]);
  assert.equal(ok[0]?.address, '140.82.112.3');
});

test('guarded lookup works with both callback conventions and blocks metadata IPs', async () => {
  const lookup = makeGuardedLookup(async (h) =>
    h === 'meta' ? [{ address: '169.254.169.254', family: 4 }] : [{ address: '140.82.112.3', family: 4 }, { address: '2606:4700::1', family: 6 }],
  );
  const single = await new Promise<unknown[]>((resolve) => lookup('ok', {}, (...args) => resolve(args)));
  assert.deepEqual(single, [null, '140.82.112.3', 4]);
  const all = await new Promise<unknown[]>((resolve) => lookup('ok', { all: true }, (...args) => resolve(args)));
  assert.equal(all[0], null);
  assert.equal((all[1] as unknown[]).length, 2);
  const v6 = await new Promise<unknown[]>((resolve) => lookup('ok', { family: 6 }, (...args) => resolve(args)));
  assert.deepEqual(v6.slice(0, 3), [null, '2606:4700::1', 6]);
  const meta = await new Promise<unknown[]>((resolve) => lookup('meta', {}, (...args) => resolve(args)));
  assert.equal((meta[0] as { code?: string }).code, 'EBLOCKED');
});

test('real https connection to a loopback host is refused before connecting', async () => {
  const { safeFetch, FetchError } = await import('../../src/github/fetcher.ts');
  await assert.rejects(
    safeFetch('https://localhost/', { allowedHosts: new Set(['localhost']), maxBytes: 100, timeoutMs: 5000 }),
    (e: unknown) => e instanceof FetchError && e.code === 'blocked_destination',
  );
});
