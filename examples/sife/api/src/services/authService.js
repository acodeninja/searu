import _ from 'lodash';
import {
  createUser,
  findByCredentials,
  findByEmail,
} from '../repositories/userRepository.js';
import { hashPassword } from '../auth/hashing.js';
import { signToken } from '../auth/jwt.js';

const tokenFor = (user) => signToken({ sub: user.id, email: user.email, role: user.role });

export const login = async (email, password) => {
  const user = await findByCredentials(email, hashPassword(password));
  if (!user) {
    const err = new Error('Invalid email or password');
    err.status = 401;
    throw err;
  }
  return { user, token: tokenFor(user) };
};

export const register = async (attributes) => {
  if (!attributes.email || !attributes.password) {
    const err = new Error('Email and password are required');
    err.status = 400;
    throw err;
  }
  if (await findByEmail(attributes.email)) {
    const err = new Error('An account with that email already exists');
    err.status = 409;
    throw err;
  }
  const merged = _.merge({}, attributes, { password_md5: hashPassword(attributes.password) });
  if (!merged.api_token) {
    merged.api_token = `sife_live_${Math.random().toString(16).slice(2, 14)}`;
  }
  const user = await createUser(merged);
  return { user, token: tokenFor(user) };
};
