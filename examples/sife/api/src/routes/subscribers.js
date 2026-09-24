import { Router } from 'express';
import { subscribe } from '../services/subscriberService.js';

export const subscribersRouter = Router();

subscribersRouter.post('/subscribers', async (req, res, next) => {
  try {
    const email = (req.body?.email ?? '').toString();
    res.status(201).json(await subscribe(email, req.body?.components));
  } catch (err) {
    next(err);
  }
});
