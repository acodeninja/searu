import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { query } from './postgres.js';
import { seedMongo } from './seed.mongo.js';

const here = dirname(fileURLToPath(import.meta.url));

export const migrate = async () => {
  const schema = await readFile(join(here, 'schema.sql'), 'utf8');
  await query(schema);
  await seedMongo();
};
