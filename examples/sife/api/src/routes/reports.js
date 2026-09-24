import { Router } from 'express';
import { requireAuth } from '../middleware/authenticate.js';
import { compute, preview } from '../services/reportService.js';
import { saveReport } from '../services/reportStoreService.js';

export const reportsRouter = Router();

reportsRouter.post('/reports/save', requireAuth, async (req, res, next) => {
  try {
    const { name, content } = req.body ?? {};
    res.status(201).json(await saveReport((name ?? 'report.txt').toString(), content));
  } catch (err) {
    next(err);
  }
});

reportsRouter.get('/reports/preview', requireAuth, (req, res, next) => {
  try {
    res.type('text/plain').send(preview(req.query.template));
  } catch (err) {
    next(err);
  }
});

reportsRouter.get('/reports/compute', requireAuth, (req, res, next) => {
  try {
    res.json({ expression: req.query.expr, value: compute(req.query.expr ?? '0') });
  } catch (err) {
    next(err);
  }
});
