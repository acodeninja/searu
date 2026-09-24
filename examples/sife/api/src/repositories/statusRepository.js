import { query } from '../db/postgres.js';

export const listComponents = async () => {
  const { rows } = await query(
    'SELECT id, name, status, position FROM components ORDER BY position ASC',
  );
  return rows;
};

export const listPublicIncidents = async () => {
  const { rows } = await query(
    `SELECT id, title, body, severity, status, component, created_at, updated_at
       FROM incidents
      WHERE is_public = true
      ORDER BY created_at DESC`,
  );
  return rows;
};

export const listUpdatesFor = async (incidentIds) => {
  if (incidentIds.length === 0) {
    return [];
  }
  const { rows } = await query(
    `SELECT incident_id, status, body, created_at
       FROM incident_updates
      WHERE incident_id = ANY($1)
      ORDER BY created_at ASC`,
    [incidentIds],
  );
  return rows;
};
