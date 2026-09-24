import { Router } from 'express';
import { statusRouter } from './status.js';

export const apiRouter = Router();

apiRouter.use(statusRouter);

apiRouter.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'sife-api' });
});
