import { Router } from 'express';
import { getStatusPage } from '../services/statusService.js';
import { incidentFeed } from '../services/feedService.js';

export const statusRouter = Router();

statusRouter.get('/status', async (req, res, next) => {
  try {
    res.json(await getStatusPage());
  } catch (err) {
    next(err);
  }
});

statusRouter.get('/status.rss', async (req, res, next) => {
  try {
    res.type('application/rss+xml').send(await incidentFeed());
  } catch (err) {
    next(err);
  }
});
