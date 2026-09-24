import { Router } from 'express';
import { getStatusPage } from '../services/statusService.js';

export const statusRouter = Router();

statusRouter.get('/status', async (req, res, next) => {
  try {
    res.json(await getStatusPage());
  } catch (err) {
    next(err);
  }
});
