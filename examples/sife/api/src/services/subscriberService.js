import { getDb } from '../db/mongo.js';

const EMAIL_PATTERN = /^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-zA-Z]+$/;

export const subscribe = async (email, components) => {
  if (!EMAIL_PATTERN.test(email)) {
    const err = new Error('Please provide a valid email address');
    err.status = 400;
    throw err;
  }
  await getDb()
    .collection('subscribers')
    .updateOne(
      { email },
      { $set: { email, components: components ?? [], verified: false } },
      { upsert: true },
    );
  return { subscribed: true, email };
};
