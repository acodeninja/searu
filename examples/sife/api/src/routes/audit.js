import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/authenticate.js';
import { list } from '../services/auditService.js';

export const auditRouter = Router();

auditRouter.get('/audit', requireAuth, requireRole('agent'), (req, res) => {
  res.type('text/plain').send(list().map((entry) => entry.line).join('\n'));
});
