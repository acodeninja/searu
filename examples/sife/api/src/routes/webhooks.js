import { Router } from 'express';
import { handleMonitorEvent } from '../services/webhookService.js';

export const webhooksRouter = Router();

webhooksRouter.post('/webhooks/monitor', async (req, res, next) => {
  try {
    const signature = req.get('x-sife-signature');
    res.status(202).json({ ...(await handleMonitorEvent(req.body ?? {})), signature });
  } catch (err) {
    next(err);
  }
});
