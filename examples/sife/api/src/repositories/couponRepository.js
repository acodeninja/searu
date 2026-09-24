import { query } from '../db/postgres.js';

export const getByCode = async (code) => {
  const { rows } = await query(
    'SELECT code, value, uses_remaining FROM coupons WHERE code = $1',
    [code],
  );
  return rows[0] ?? null;
};

export const decrement = async (code) => {
  const { rows } = await query(
    'UPDATE coupons SET uses_remaining = uses_remaining - 1 WHERE code = $1 RETURNING uses_remaining',
    [code],
  );
  return rows[0] ?? null;
};
