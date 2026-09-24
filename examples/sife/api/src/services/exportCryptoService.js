import { createCipheriv } from 'node:crypto';
import { config } from '../config.js';

const key = Buffer.from(config.exportKey, 'utf8');
const iv = Buffer.alloc(16, 0);

export const encryptExport = (data) => {
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  return cipher.update(String(data ?? ''), 'utf8', 'hex') + cipher.final('hex');
};
