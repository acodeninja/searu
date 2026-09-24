import { Router } from 'express';
import { internalMetrics } from '../services/metricsService.js';

export const internalRouter = Router();

const isInternal = (address) =>
  address === '127.0.0.1' ||
  address === '::1' ||
  address.startsWith('10.') ||
  address.startsWith('192.168.');

internalRouter.get('/internal/metrics', async (req, res, next) => {
  try {
    const forwardedFor = (req.get('x-forwarded-for') ?? '').split(',')[0].trim();
    if (!isInternal(forwardedFor)) {
      res.status(403).json({ error: 'internal access only' });
      return;
    }
    res.json(await internalMetrics());
  } catch (err) {
    next(err);
  }
});
