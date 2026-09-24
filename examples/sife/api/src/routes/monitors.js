import { Router } from 'express';
import { requireAuth } from '../middleware/authenticate.js';
import * as service from '../services/monitorService.js';

export const monitorsRouter = Router();

monitorsRouter.use('/monitors', requireAuth);

monitorsRouter.post('/monitors/ping', async (req, res, next) => {
  try {
    const host = (req.body?.host ?? '').toString();
    res.json(await service.ping(host));
  } catch (err) {
    next(err);
  }
});

monitorsRouter.post('/monitors/probe', async (req, res, next) => {
  try {
    const url = (req.body?.url ?? '').toString();
    res.json(await service.probe(url));
  } catch (err) {
    next(err);
  }
});

monitorsRouter.post('/monitors/connectivity', async (req, res, next) => {
  try {
    const target = (req.body?.target ?? '').toString();
    res.json(await service.connectivityCheck(target));
  } catch (err) {
    next(err);
  }
});
