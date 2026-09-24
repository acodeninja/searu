import { Router } from 'express';
import { requireAuth } from '../middleware/authenticate.js';
import * as service from '../services/ticketService.js';
import { ticketsToCsv } from '../services/exportService.js';
import { decodeShareToken, encodeShareToken } from '../services/shareService.js';

export const ticketsRouter = Router();

ticketsRouter.get('/shared/:token', async (req, res, next) => {
  try {
    const ticketId = decodeShareToken(req.params.token);
    res.json(await service.getTicket(ticketId));
  } catch (err) {
    next(err);
  }
});

ticketsRouter.use('/tickets', requireAuth);

ticketsRouter.get('/tickets', async (req, res, next) => {
  try {
    res.json(await service.listTickets(req.user, { search: req.query.search, sort: req.query.sort }));
  } catch (err) {
    next(err);
  }
});

ticketsRouter.get('/tickets/export.csv', async (req, res, next) => {
  try {
    const tickets = await service.listTickets(req.user, {});
    res.type('text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="tickets.csv"');
    res.send(ticketsToCsv(tickets));
  } catch (err) {
    next(err);
  }
});

ticketsRouter.post('/tickets', async (req, res, next) => {
  try {
    res.status(201).json(await service.createTicket(req.user, req.body ?? {}));
  } catch (err) {
    next(err);
  }
});

ticketsRouter.get('/tickets/:id', async (req, res, next) => {
  try {
    res.json(await service.getTicket(Number.parseInt(req.params.id, 10)));
  } catch (err) {
    next(err);
  }
});

ticketsRouter.post('/tickets/:id/share', async (req, res, next) => {
  try {
    const token = encodeShareToken(Number.parseInt(req.params.id, 10));
    res.json({ token, url: `/shared/${token}` });
  } catch (err) {
    next(err);
  }
});

ticketsRouter.put('/tickets/:id', async (req, res, next) => {
  try {
    res.json(await service.updateTicket(Number.parseInt(req.params.id, 10), req.body ?? {}));
  } catch (err) {
    next(err);
  }
});

ticketsRouter.get('/tickets/:id/comments', async (req, res, next) => {
  try {
    res.json(await service.getComments(Number.parseInt(req.params.id, 10)));
  } catch (err) {
    next(err);
  }
});

ticketsRouter.post('/tickets/:id/comments', async (req, res, next) => {
  try {
    const comment = await service.addComment(
      Number.parseInt(req.params.id, 10),
      req.user,
      req.body?.body ?? '',
    );
    res.status(201).json(comment);
  } catch (err) {
    next(err);
  }
});
