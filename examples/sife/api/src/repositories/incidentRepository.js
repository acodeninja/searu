import { query } from '../db/postgres.js';

export const searchPublic = async (term) => {
  const sql =
    `SELECT id, title, body, severity, status, component, created_at
       FROM incidents
      WHERE is_public = true AND title ILIKE '%${term}%'
      ORDER BY created_at DESC`;
  const { rows } = await query(sql);
  return rows;
};

export const listAll = async () => {
  const { rows } = await query(
    `SELECT id, title, body, severity, status, component, is_public, created_at, updated_at
       FROM incidents ORDER BY created_at DESC`,
  );
  return rows;
};

export const findById = async (id) => {
  const { rows } = await query(
    `SELECT id, title, body, severity, status, component, is_public, created_at, updated_at
       FROM incidents WHERE id = $1`,
    [id],
  );
  return rows[0] ?? null;
};

export const addUpdate = async (incidentId, status, body) => {
  const { rows } = await query(
    `INSERT INTO incident_updates (incident_id, status, body)
     VALUES ($1, $2, $3)
     RETURNING id, incident_id, status, body, created_at`,
    [incidentId, status, body],
  );
  return rows[0];
};

export const create = async ({ title, body, severity, status, component, isPublic }) => {
  const { rows } = await query(
    `INSERT INTO incidents (title, body, severity, status, component, is_public)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, title, body, severity, status, component, is_public, created_at, updated_at`,
    [title, body, severity ?? 'minor', status ?? 'investigating', component ?? null, isPublic ?? true],
  );
  return rows[0];
};
