import { Router } from 'express';
import { requireAuth } from '../middleware/authenticate.js';
import { addIntegration, listIntegrations } from '../services/integrationService.js';

export const integrationsRouter = Router();

integrationsRouter.use('/integrations', requireAuth);

integrationsRouter.get('/integrations', async (req, res, next) => {
  try {
    res.json(await listIntegrations());
  } catch (err) {
    next(err);
  }
});

integrationsRouter.post('/integrations', async (req, res, next) => {
  try {
    const { provider, apiKey } = req.body ?? {};
    res.status(201).json(await addIntegration(req.user.email, provider, apiKey));
  } catch (err) {
    next(err);
  }
});
