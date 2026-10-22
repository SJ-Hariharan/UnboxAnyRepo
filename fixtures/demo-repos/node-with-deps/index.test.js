const { test } = require('node:test');
const assert = require('node:assert/strict');
const ms = require('ms');

test('parses durations', () => {
  assert.equal(ms('2s'), 2000);
});
