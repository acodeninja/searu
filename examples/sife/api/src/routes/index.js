import { Router } from 'express';
import { statusRouter } from './status.js';
import { usersRouter } from './users.js';
import { ticketsRouter } from './tickets.js';
import { incidentsRouter } from './incidents.js';
import { attachmentsRouter } from './attachments.js';

export const apiRouter = Router();

apiRouter.use(statusRouter);
apiRouter.use(usersRouter);
apiRouter.use(ticketsRouter);
apiRouter.use(incidentsRouter);
apiRouter.use(attachmentsRouter);

apiRouter.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'sife-api' });
});
