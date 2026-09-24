import pg from 'pg';
import { config } from '../config.js';

const { Pool } = pg;

let pool;

export const getPool = () => {
  if (!pool) {
    pool = new Pool(config.postgres);
  }
  return pool;
};

export const query = (text, params) => getPool().query(text, params);

export const closePool = async () => {
  if (pool) {
    await pool.end();
    pool = undefined;
  }
};
