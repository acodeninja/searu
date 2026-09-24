import { query } from '../db/postgres.js';
import { list } from './auditService.js';

export const internalMetrics = async () => {
  const users = await query('SELECT count(*)::int AS total, role FROM users GROUP BY role');
  const tickets = await query('SELECT count(*)::int AS total FROM tickets');
  return {
    usersByRole: users.rows,
    tickets: tickets.rows[0].total,
    recentSignIns: list()
      .filter((entry) => entry.event === 'login')
      .slice(0, 10)
      .map((entry) => ({ email: entry.email, outcome: entry.outcome })),
  };
};
