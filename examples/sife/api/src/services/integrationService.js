import { getDb } from '../db/mongo.js';

export const listIntegrations = () =>
  getDb().collection('integrations').find({}).project({ _id: 0 }).toArray();

export const addIntegration = async (owner, provider, apiKey) => {
  await getDb()
    .collection('integrations')
    .insertOne({ owner, provider, apiKey, createdAt: new Date().toISOString() });
  return { saved: true, provider };
};
