import { test } from 'node:test';
import assert from 'node:assert/strict';
import { add, mean } from '../src/math.js';

test('add', () => {
  assert.equal(add(2, 3), 5);
});

test('mean', () => {
  assert.equal(mean([1, 2, 3, 4]), 2.5);
  assert.throws(() => mean([]), RangeError);
});
