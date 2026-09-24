import { getDb } from '../db/mongo.js';

export const search = (filter) =>
  getDb()
    .collection('kb_articles')
    .find(filter)
    .project({ _id: 0 })
    .toArray();

export const listPublished = () => search({ published: true });
