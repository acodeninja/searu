import { test } from 'node:test';
import assert from 'node:assert/strict';
import { signToken, verifyToken } from './jwt.js';

test('signs and verifies a token round-trip', () => {
  const token = signToken({ sub: 7, role: 'agent' });
  const payload = verifyToken(token);
  assert.equal(payload.sub, 7);
  assert.equal(payload.role, 'agent');
});

test('rejects a tampered HS256 signature', () => {
  const token = signToken({ sub: 1 });
  const [header, body] = token.split('.');
  assert.throws(() => verifyToken(`${header}.${body}.deadbeef`));
});
