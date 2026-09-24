import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/authenticate.js';
import * as service from '../services/incidentService.js';

export const incidentsRouter = Router();

incidentsRouter.get('/incidents/search', async (req, res, next) => {
  try {
    res.json(await service.searchPublic(req.query.q));
  } catch (err) {
    next(err);
  }
});

incidentsRouter.get('/incidents', requireAuth, async (req, res, next) => {
  try {
    res.json(await service.listAll());
  } catch (err) {
    next(err);
  }
});

incidentsRouter.post('/incidents', requireAuth, requireRole('agent'), async (req, res, next) => {
  try {
    res.status(201).json(await service.createIncident(req.body ?? {}));
  } catch (err) {
    next(err);
  }
});

incidentsRouter.get('/incidents/:id', async (req, res, next) => {
  try {
    res.json(await service.getIncident(Number.parseInt(req.params.id, 10)));
  } catch (err) {
    next(err);
  }
});

incidentsRouter.get('/incidents/:id/reactions', async (req, res, next) => {
  try {
    res.json(await service.getReactions(req.params.id));
  } catch (err) {
    next(err);
  }
});

incidentsRouter.post('/incidents/:id/reactions', async (req, res, next) => {
  try {
    const emoji = (req.body?.emoji ?? '👍').toString();
    res.json(await service.react(req.params.id, emoji));
  } catch (err) {
    next(err);
  }
});
