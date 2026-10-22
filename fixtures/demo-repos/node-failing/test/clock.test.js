const { test } = require('node:test');
const assert = require('node:assert/strict');

test('passes', () => {
  assert.equal(1 + 1, 2);
});

test('fails on purpose (demo fixture)', () => {
  assert.equal(0.1 + 0.2, 0.3, 'floating point says no');
});
