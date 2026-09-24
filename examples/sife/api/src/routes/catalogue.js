import { Router } from 'express';
import { search } from '../services/catalogueService.js';

export const catalogueRouter = Router();

catalogueRouter.get('/catalogue/search', (req, res, next) => {
  try {
    res.json(search((req.query.q ?? '').toString()));
  } catch (err) {
    next(err);
  }
});
