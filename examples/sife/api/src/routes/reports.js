import { Router } from 'express';
import { requireAuth } from '../middleware/authenticate.js';
import { preview } from '../services/reportService.js';

export const reportsRouter = Router();

reportsRouter.get('/reports/preview', requireAuth, (req, res, next) => {
  try {
    res.type('text/plain').send(preview(req.query.template));
  } catch (err) {
    next(err);
  }
});
