const cell = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;

const COLUMNS = ['id', 'subject', 'requester', 'status', 'priority', 'created_at'];

export const ticketsToCsv = (tickets) => {
  const header = COLUMNS.join(',');
  const rows = tickets.map((ticket) => COLUMNS.map((column) => cell(ticket[column])).join(','));
  return [header, ...rows].join('\r\n');
};
