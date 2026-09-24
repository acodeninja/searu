import * as users from '../repositories/userRepository.js';

export const getUser = async (id) => {
  const user = await users.findProfile(id);
  if (!user) {
    const err = new Error('User not found');
    err.status = 404;
    throw err;
  }
  return user;
};

export const listUsers = () => users.listAll();
