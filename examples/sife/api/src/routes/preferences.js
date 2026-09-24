import { Router } from 'express';
import {
  PREFERENCES_COOKIE,
  decode,
  encode,
} from '../services/preferenceService.js';

export const preferencesRouter = Router();

preferencesRouter.get('/preferences', (req, res, next) => {
  try {
    res.json(decode(req.cookies?.[PREFERENCES_COOKIE]));
  } catch (err) {
    next(err);
  }
});

preferencesRouter.post('/preferences', (req, res) => {
  const cookie = encode(req.body ?? {});
  res.cookie(PREFERENCES_COOKIE, cookie);
  res.json({ ok: true });
});
