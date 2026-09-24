import { Router } from 'express';
import { requireAuth } from '../middleware/authenticate.js';
import * as service from '../services/ticketService.js';

export const ticketsRouter = Router();

ticketsRouter.use('/tickets', requireAuth);

ticketsRouter.get('/tickets', async (req, res, next) => {
  try {
    res.json(await service.listTickets(req.user, { search: req.query.search, sort: req.query.sort }));
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
