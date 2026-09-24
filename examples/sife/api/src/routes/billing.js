import { Router } from 'express';
import { requireAuth } from '../middleware/authenticate.js';
import * as service from '../services/billingService.js';

export const billingRouter = Router();

billingRouter.use('/billing', requireAuth);

billingRouter.get('/billing', async (req, res, next) => {
  try {
    res.json(await service.currentPlan(req.user.id));
  } catch (err) {
    next(err);
  }
});

billingRouter.post('/billing/subscribe', async (req, res, next) => {
  try {
    res.json(await service.subscribe(req.user.id, req.body ?? {}));
  } catch (err) {
    next(err);
  }
});

billingRouter.post('/billing/refund', async (req, res, next) => {
  try {
    res.json(await service.refund(req.user.id, req.body?.amount));
  } catch (err) {
    next(err);
  }
});

billingRouter.post('/billing/redeem', async (req, res, next) => {
  try {
    res.json(await service.redeem(req.user.id, (req.body?.code ?? '').toString()));
  } catch (err) {
    next(err);
  }
});
