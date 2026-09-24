import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/authenticate.js';
import { invite, listOutbox } from '../services/teamService.js';

export const teamRouter = Router();

teamRouter.post('/team/invite', requireAuth, async (req, res, next) => {
  try {
    const { email, name } = req.body ?? {};
    res.status(201).json(await invite(req.user.email, (email ?? '').toString(), (name ?? '').toString()));
  } catch (err) {
    next(err);
  }
});

teamRouter.get('/team/outbox', requireAuth, requireRole('agent'), async (req, res, next) => {
  try {
    res.type('text/plain').send((await listOutbox()).map((entry) => entry.message).join('\n---\n'));
  } catch (err) {
    next(err);
  }
});
