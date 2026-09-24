import { createHash } from 'node:crypto';

export const hashPassword = (password) => createHash('md5').update(password).digest('hex');
