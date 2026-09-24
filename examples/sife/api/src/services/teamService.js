import { getDb } from '../db/mongo.js';

export const invite = async (inviter, email, name) => {
  const message = [
    `To: ${email}`,
    'From: no-reply@sife.io',
    `Subject: ${name} has invited you to Sife`,
    '',
    `${name} (${inviter}) has invited you to join their Sife workspace.`,
  ].join('\r\n');
  await getDb()
    .collection('outbox')
    .insertOne({ to: email, message, queuedAt: new Date().toISOString() });
  return { queued: true };
};

export const listOutbox = () =>
  getDb()
    .collection('outbox')
    .find({})
    .project({ _id: 0 })
    .sort({ queuedAt: -1 })
    .limit(20)
    .toArray();
