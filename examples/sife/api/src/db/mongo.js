import { MongoClient } from 'mongodb';
import { config } from '../config.js';

let client;
let database;

export const connectMongo = async () => {
  if (!database) {
    client = new MongoClient(config.mongo.url);
    await client.connect();
    database = client.db(config.mongo.database);
  }
  return database;
};

export const getDb = () => {
  if (!database) {
    throw new Error('Mongo connection not initialised');
  }
  return database;
};

export const closeMongo = async () => {
  if (client) {
    await client.close();
    client = undefined;
    database = undefined;
  }
};
