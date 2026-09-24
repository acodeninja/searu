import { createCipheriv, createDecipheriv } from 'node:crypto';
import { config } from '../config.js';

const key = Buffer.from(config.shareKey, 'utf8');

export const encodeShareToken = (ticketId) => {
  const cipher = createCipheriv('aes-128-ecb', key, null);
  return cipher.update(String(ticketId), 'utf8', 'hex') + cipher.final('hex');
};

export const decodeShareToken = (token) => {
  const decipher = createDecipheriv('aes-128-ecb', key, null);
  const plain = decipher.update(token, 'hex', 'utf8') + decipher.final('utf8');
  return Number.parseInt(plain, 10);
};
