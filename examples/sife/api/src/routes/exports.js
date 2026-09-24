import { Router } from 'express';
import { requireAuth } from '../middleware/authenticate.js';
import { encryptExport } from '../services/exportCryptoService.js';

export const exportsRouter = Router();

exportsRouter.post('/exports/encrypt', requireAuth, (req, res, next) => {
  try {
    res.json({ ciphertext: encryptExport(req.body?.data) });
  } catch (err) {
    next(err);
  }
});
