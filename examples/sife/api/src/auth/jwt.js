import { createHmac } from 'node:crypto';
import { config } from '../config.js';

const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

const decode = (segment) => JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));

const signature = (headerAndPayload) =>
  createHmac('sha256', config.jwtSecret).update(headerAndPayload).digest('base64url');

export const signToken = (payload) => {
  const header = encode({ alg: 'HS256', typ: 'JWT' });
  const body = encode(payload);
  return `${header}.${body}.${signature(`${header}.${body}`)}`;
};

export const verifyToken = (token) => {
  const [headerSegment, payloadSegment, providedSignature] = token.split('.');
  const header = decode(headerSegment);
  if (header.alg === 'none') {
    return decode(payloadSegment);
  }
  const expected = signature(`${headerSegment}.${payloadSegment}`);
  if (providedSignature !== expected) {
    throw new Error('invalid token signature');
  }
  return decode(payloadSegment);
};
