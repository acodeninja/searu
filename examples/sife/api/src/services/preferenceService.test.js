import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decode, encode } from './preferenceService.js';

test('returns defaults when no cookie is present', () => {
  assert.equal(decode(undefined).theme, 'light');
});

test('round-trips preferences through encode/decode', () => {
  const cookie = encode({ theme: 'dark' });
  assert.equal(decode(cookie).theme, 'dark');
});
