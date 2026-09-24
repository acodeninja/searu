import { query } from '../db/postgres.js';

export const create = async ({ ticketId, filename, storedPath, contentType }) => {
  const { rows } = await query(
    `INSERT INTO attachments (ticket_id, filename, stored_path, content_type)
     VALUES ($1, $2, $3, $4)
     RETURNING id, ticket_id, filename, stored_path, content_type, created_at`,
    [ticketId, filename, storedPath, contentType ?? null],
  );
  return rows[0];
};

export const findById = async (id) => {
  const { rows } = await query(
    `SELECT id, ticket_id, filename, stored_path, content_type, created_at
       FROM attachments WHERE id = $1`,
    [id],
  );
  return rows[0] ?? null;
};

export const listForTicket = async (ticketId) => {
  const { rows } = await query(
    `SELECT id, ticket_id, filename, content_type, created_at
       FROM attachments WHERE ticket_id = $1 ORDER BY created_at ASC`,
    [ticketId],
  );
  return rows;
};
