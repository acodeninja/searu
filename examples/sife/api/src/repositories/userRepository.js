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
    `SELECT id, email, role, full_name, organisation, phone, api_token, plan, seats, created_at
       FROM users WHERE id = $1`,
    [id],
  );
  return rows[0] ?? null;
};

export const findProfile = async (id) => {
  const { rows } = await query(
    `SELECT id, email, password_md5, full_name, role, organisation, phone, api_token,
            security_question, security_answer, created_at
       FROM users WHERE id = $1`,
    [id],
  );
  return rows[0] ?? null;
};

export const setSecurityQuestion = async (id, questionText, answer) => {
  const { rows } = await query(
    'UPDATE users SET security_question = $2, security_answer = $3 WHERE id = $1 RETURNING id',
    [id, questionText, answer],
  );
  return rows[0] ?? null;
};

export const findSecurityByEmail = async (email) => {
  const { rows } = await query(
    'SELECT id, email, role, security_answer FROM users WHERE email = $1',
    [email],
  );
  return rows[0] ?? null;
};

export const listAll = async () => {
  const { rows } = await query(
    `SELECT id, email, full_name, role, organisation, phone, created_at
       FROM users ORDER BY id ASC`,
  );
  return rows;
};

export const findByEmail = async (email) => {
  const { rows } = await query('SELECT id, email, role FROM users WHERE email = $1', [email]);
  return rows[0] ?? null;
};

export const updatePassword = async (id, passwordMd5) => {
  const { rows } = await query(
    'UPDATE users SET password_md5 = $2 WHERE id = $1 RETURNING id, email, role',
    [id, passwordMd5],
  );
  return rows[0] ?? null;
};

export const addCredit = async (id, amount) => {
  const { rows } = await query(
    'UPDATE users SET credit = credit + $2 WHERE id = $1 RETURNING id, credit',
    [id, amount],
  );
  return rows[0] ?? null;
};

export const updatePlan = async (id, plan, seats) => {
  const { rows } = await query(
    'UPDATE users SET plan = $2, seats = $3 WHERE id = $1 RETURNING id, email, plan, seats',
    [id, plan, seats],
  );
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
