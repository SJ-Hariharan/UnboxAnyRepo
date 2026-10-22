import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RunLog, sanitizeLine } from '../../src/runs/logs.ts';
import { Redactor } from '../../src/runs/redact.ts';

test('sanitizeLine strips terminal escapes and control characters, keeps text', () => {
  assert.equal(sanitizeLine('\u001b[1;31mFAIL\u001b[0m test'), 'FAIL test');
  assert.equal(sanitizeLine('\u001b]8;;https://evil\u0007link\u001b]8;;\u0007'), 'link');
  assert.equal(sanitizeLine('progress 10%\rprogress 100%'), 'progress 100%');
  assert.equal(sanitizeLine('a\u0000b\u0007c\u007fd\u0085e'), 'abcde');
  assert.equal(sanitizeLine('tab\there'), 'tab    here');
  assert.equal(sanitizeLine('<img src=x onerror=alert(1)>'), '<img src=x onerror=alert(1)>');
  assert.ok(sanitizeLine('x'.repeat(10000)).endsWith('[line truncated]'));
});

test('multi-byte characters split across chunks are decoded correctly', () => {
  const log = new RunLog({ headBytes: 1024, tailBytes: 1024 });
  const bytes = Buffer.from('héllo wörld ✓\n');
  log.write('out', bytes.subarray(0, 2));
  log.write('out', bytes.subarray(2, 13));
  log.write('out', bytes.subarray(13));
  assert.equal(log.retained()[0]?.text, 'héllo wörld ✓');
});

test('streams are line-buffered independently and flushed at the end', () => {
  const log = new RunLog({ headBytes: 1024, tailBytes: 1024 });
  log.write('a', 'one-');
  log.write('b', 'two\n');
  log.write('a', 'done');
  log.end('a');
  assert.deepEqual(log.retained().map((l) => l.text), ['two', 'one-done']);
});

test('head + tail retention with an explicit truncation marker', () => {
  let truncatedEvents = 0;
  const log = new RunLog({ headBytes: 100, tailBytes: 50 });
  log.events = { onTruncated: () => truncatedEvents++ };
  for (let i = 0; i < 100; i++) log.write('out', `line-${String(i).padStart(3, '0')}\n`);
  const lines = log.retained();
  assert.equal(truncatedEvents, 1);
  assert.equal(lines[0]?.text, 'line-000');
  assert.equal(lines.at(-1)?.text, 'line-099');
  assert.ok(lines.some((l) => l.kind === 'system' && /omitted/.test(l.text)));
  assert.ok(log.toText().length < 400);
});

test('redactor covers configured secrets, common token formats and PEM blocks', () => {
  const r = new Redactor(['super-secret-config-value']);
  const cases: [string, RegExp][] = [
    ['value super-secret-config-value here', /super-secret/],
    ['ghp_abcdefghijklmnopqrstuvwxyz0123456789', /ghp_/],
    ['github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz', /github_pat_/],
    ['AKIAABCDEFGHIJKLMNOP', /AKIA/],
    ['Authorization: Bearer abc.def.ghi', /abc\.def/],
    ['https://user:hunter2@example.com/x', /hunter2/],
    ['password=hunter2hunter2', /hunter2/],
    ['xoxb-1234567890-abcdefghij', /xoxb-1234/],
  ];
  for (const [input, leaked] of cases) assert.doesNotMatch(r.line(input), leaked, input);
  const pem = new Redactor();
  const out = ['-----BEGIN RSA PRIVATE KEY-----', 'MIIEowIBAAKCAQEA', '-----END RSA PRIVATE KEY-----', 'after'].map((l) => pem.line(l));
  assert.deepEqual(out.slice(0, 3), Array(3).fill('[REDACTED:private-key]'));
  assert.equal(out[3], 'after');
});
