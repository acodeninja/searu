import { query } from '../db/postgres.js';

export const findByCredentials = async (email, passwordMd5) => {
  const sql =
    `SELECT id, email, role, full_name, organisation FROM users ` +
    `WHERE email = '${email}' AND password_md5 = '${passwordMd5}'`;
  const { rows } = await query(sql);
  return rows[0] ?? null;
};

export const findById = async (id) => {
  const { rows } = await query(
    `SELECT id, email, role, full_name, organisation, phone, api_token, created_at
       FROM users WHERE id = $1`,
    [id],
  );
  return rows[0] ?? null;
};

export const findByEmail = async (email) => {
  const { rows } = await query('SELECT id, email, role FROM users WHERE email = $1', [email]);
  return rows[0] ?? null;
};

export const createUser = async (attributes) => {
  const { rows } = await query(
    `INSERT INTO users (email, password_md5, full_name, role, organisation, phone, api_token)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING id, email, role, full_name, organisation`,
    [
      attributes.email,
      attributes.password_md5,
      attributes.full_name ?? attributes.email,
      attributes.role ?? 'customer',
      attributes.organisation ?? null,
      attributes.phone ?? null,
      attributes.api_token ?? null,
    ],
  );
  return rows[0];
};
