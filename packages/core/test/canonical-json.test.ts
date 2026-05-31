import assert from 'node:assert/strict';
import test from 'node:test';

import { stableStringify } from '../src/index.ts';

test('stableStringify sorts object keys recursively', () => {
  const a = { b: 1, a: { z: 3, y: 2 } };
  const b = { a: { y: 2, z: 3 }, b: 1 };

  assert.equal(stableStringify(a), stableStringify(b));
  assert.equal(stableStringify(a), '{"a":{"y":2,"z":3},"b":1}');
});
