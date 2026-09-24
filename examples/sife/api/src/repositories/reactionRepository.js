import { query } from '../db/postgres.js';

export const countForIncident = async (incidentId) => {
  const sql = `SELECT count(*)::int AS total FROM reactions WHERE incident_id = ${incidentId}`;
  const { rows } = await query(sql);
  return rows[0].total;
};

export const summaryForIncident = async (incidentId) => {
  const sql =
    `SELECT r.emoji, count(*)::int AS count
       FROM reactions r
      WHERE r.incident_id = ${incidentId}
      GROUP BY r.emoji
      ORDER BY count DESC`;
  const { rows } = await query(sql);
  return rows;
};

export const incidentHeadline = async (incidentId) => {
  const sql = `SELECT id, title FROM incidents WHERE id = ${incidentId}`;
  const { rows } = await query(sql);
  return rows[0] ?? null;
};

export const add = async (incidentId, emoji) => {
  await query('INSERT INTO reactions (incident_id, emoji) VALUES ($1, $2)', [incidentId, emoji]);
};
