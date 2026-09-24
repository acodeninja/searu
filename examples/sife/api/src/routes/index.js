import { Router } from 'express';
import { statusRouter } from './status.js';
import { usersRouter } from './users.js';

export const apiRouter = Router();

apiRouter.use(statusRouter);
apiRouter.use(usersRouter);

apiRouter.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'sife-api' });
});
