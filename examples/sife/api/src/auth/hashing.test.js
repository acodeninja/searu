import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword } from './hashing.js';

test('hashes a password to its MD5 digest', () => {
  assert.equal(hashPassword('123456'), 'e10adc3949ba59abbe56e057f20f883e');
});
