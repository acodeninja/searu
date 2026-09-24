import { Router } from 'express';
import { statusRouter } from './status.js';
import { usersRouter } from './users.js';
import { ticketsRouter } from './tickets.js';
import { incidentsRouter } from './incidents.js';
import { attachmentsRouter } from './attachments.js';
import { monitorsRouter } from './monitors.js';
import { reportsRouter } from './reports.js';
import { kbRouter } from './kb.js';
import { preferencesRouter } from './preferences.js';
import { redirectRouter } from './redirect.js';
import { subscribersRouter } from './subscribers.js';
import { billingRouter } from './billing.js';
import { integrationsRouter } from './integrations.js';

export const apiRouter = Router();

apiRouter.use(statusRouter);
apiRouter.use(usersRouter);
apiRouter.use(ticketsRouter);
apiRouter.use(incidentsRouter);
apiRouter.use(attachmentsRouter);
apiRouter.use(monitorsRouter);
apiRouter.use(reportsRouter);
apiRouter.use(kbRouter);
apiRouter.use(preferencesRouter);
apiRouter.use(redirectRouter);
apiRouter.use(subscribersRouter);
apiRouter.use(billingRouter);
apiRouter.use(integrationsRouter);

apiRouter.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'sife-api' });
});
