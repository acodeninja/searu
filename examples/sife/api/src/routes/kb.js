import { Router } from 'express';
import * as service from '../services/kbService.js';

export const kbRouter = Router();

kbRouter.get('/kb', async (req, res, next) => {
  try {
    res.json(await service.listPublished());
  } catch (err) {
    next(err);
  }
});

kbRouter.post('/kb/search', async (req, res, next) => {
  try {
    const body = req.body ?? {};
    const filter = Object.keys(body).length > 0 ? body : { published: true };
    res.json(await service.search(filter));
  } catch (err) {
    next(err);
  }
});
