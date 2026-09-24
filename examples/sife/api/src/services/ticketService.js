import * as tickets from '../repositories/ticketRepository.js';

const staff = (user) => user.role === 'agent' || user.role === 'admin';

export const listTickets = (user, { search, sort }) =>
  tickets.search({ term: search, sort, ownerId: staff(user) ? null : user.id });

export const getTicket = async (id) => {
  const ticket = await tickets.findById(id);
  if (!ticket) {
    const err = new Error('Ticket not found');
    err.status = 404;
    throw err;
  }
  return ticket;
};

export const createTicket = (user, body) =>
  tickets.create({
    userId: user.id,
    subject: body.subject,
    body: body.body,
    priority: body.priority,
    isPublic: body.is_public,
  });

export const updateTicket = (id, attributes) => tickets.update(id, attributes);

export const getComments = (ticketId) => tickets.listComments(ticketId);

export const addComment = (ticketId, user, body) => tickets.addComment(ticketId, user.id, body);
