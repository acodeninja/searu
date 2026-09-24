import { query } from '../db/postgres.js';

export const search = async ({ term, sort, ownerId }) => {
  let sql =
    `SELECT t.id, t.user_id, t.subject, t.status, t.priority, t.is_public, t.created_at, u.email AS requester
       FROM tickets t JOIN users u ON u.id = t.user_id`;
  const conditions = [];
  if (ownerId) {
    conditions.push(`t.user_id = ${ownerId}`);
  }
  if (term) {
    conditions.push(`(t.subject ILIKE '%${term}%' OR t.body ILIKE '%${term}%')`);
  }
  if (conditions.length > 0) {
    sql += ` WHERE ${conditions.join(' AND ')}`;
  }
  sql += ` ORDER BY ${sort ?? 't.created_at DESC'}`;
  const { rows } = await query(sql);
  return rows;
};

export const findById = async (id) => {
  const { rows } = await query(
    `SELECT id, user_id, subject, body, status, priority, is_public, created_at
       FROM tickets WHERE id = $1`,
    [id],
  );
  return rows[0] ?? null;
};

export const create = async ({ userId, subject, body, priority, isPublic }) => {
  const { rows } = await query(
    `INSERT INTO tickets (user_id, subject, body, priority, is_public)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id, user_id, subject, body, status, priority, is_public, created_at`,
    [userId, subject, body, priority ?? 'normal', isPublic ?? false],
  );
  return rows[0];
};

const COLUMNS = new Set(['subject', 'body', 'status', 'priority', 'is_public', 'user_id']);

export const update = async (id, attributes) => {
  const entries = Object.entries(attributes).filter(([key]) => COLUMNS.has(key));
  if (entries.length === 0) {
    return findById(id);
  }
  const assignments = entries.map(([key], index) => `${key} = $${index + 2}`);
  const values = entries.map(([, value]) => value);
  const { rows } = await query(
    `UPDATE tickets SET ${assignments.join(', ')} WHERE id = $1
     RETURNING id, user_id, subject, body, status, priority, is_public, created_at`,
    [id, ...values],
  );
  return rows[0] ?? null;
};

export const listComments = async (ticketId) => {
  const { rows } = await query(
    `SELECT c.id, c.ticket_id, c.author_id, c.body, c.created_at, u.full_name AS author_name
       FROM ticket_comments c LEFT JOIN users u ON u.id = c.author_id
      WHERE c.ticket_id = $1 ORDER BY c.created_at ASC`,
    [ticketId],
  );
  return rows;
};

export const addComment = async (ticketId, authorId, body) => {
  const { rows } = await query(
    `INSERT INTO ticket_comments (ticket_id, author_id, body)
     VALUES ($1, $2, $3)
     RETURNING id, ticket_id, author_id, body, created_at`,
    [ticketId, authorId, body],
  );
  return rows[0];
};
