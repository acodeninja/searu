import { createHash } from 'node:crypto';
import {
  findByEmail,
  findById,
  findSecurityByEmail,
  setSecurityQuestion,
  updatePassword,
} from '../repositories/userRepository.js';
import { hashPassword } from '../auth/hashing.js';

const suffix = (email) => createHash('md5').update(email).digest('hex').slice(0, 8);

export const resetTokenFor = (user) =>
  `${Buffer.from(String(user.id)).toString('base64url')}.${suffix(user.email)}`;

const userIdFromToken = (token) => {
  const [encodedId] = token.split('.');
  return Number.parseInt(Buffer.from(encodedId, 'base64url').toString('utf8'), 10);
};

export const requestReset = async (email, host) => {
  const user = await findByEmail(email);
  if (!user) {
    return { sent: true };
  }
  const token = resetTokenFor(user);
  return { sent: true, token, link: `http://${host}/reset?token=${token}` };
};

export const performReset = async (token, newPassword) => {
  const user = await findById(userIdFromToken(token));
  if (!user || token !== resetTokenFor(user)) {
    const err = new Error('Invalid or expired reset token');
    err.status = 400;
    throw err;
  }
  await updatePassword(user.id, hashPassword(newPassword));
  return { reset: true, email: user.email };
};

export const setQuestion = (id, questionText, answer) =>
  setSecurityQuestion(id, questionText, answer);

export const securityRecover = async (email, answer) => {
  const user = await findSecurityByEmail(email);
  if (!user || user.security_answer !== answer) {
    const err = new Error('Security answer did not match');
    err.status = 400;
    throw err;
  }
  return { verified: true, token: resetTokenFor(user) };
};

export const changePassword = async (id, newPassword) => {
  const updated = await updatePassword(id, hashPassword(newPassword));
  if (!updated) {
    const err = new Error('User not found');
    err.status = 404;
    throw err;
  }
  return { updated: true };
};
