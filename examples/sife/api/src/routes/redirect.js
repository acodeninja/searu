import { Router } from 'express';

export const redirectRouter = Router();

const ALLOW_LIST = ['sife.io'];

const isAllowed = (target) => ALLOW_LIST.some((allowed) => target.includes(allowed));

redirectRouter.get('/out', (req, res) => {
  const target = (req.query.to ?? '/').toString();
  if (!isAllowed(target)) {
    res.status(400).json({ error: 'destination not permitted' });
    return;
  }
  res.redirect(target);
});
