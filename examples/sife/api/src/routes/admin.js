import { Router } from 'express';
import { requireAuth } from '../middleware/authenticate.js';
import { config } from '../config.js';

export const adminRouter = Router();

adminRouter.get('/admin/settings', requireAuth, (req, res) => {
  res.json({
    jwtSecret: config.jwtSecret,
    sessionSecret: config.sessionSecret,
    shareKey: config.shareKey,
    postgres: config.postgres,
    mongo: config.mongo,
    smtp: {
      host: 'smtp.sendgrid.net',
      user: 'apikey',
      password: process.env.SMTP_PASSWORD ?? 'SG.4bQp8s2ZQ0Ke9nGqk3xytA.Rr7cL1xuJ0mWv9d2sQ',
    },
    featureFlags: { signups: true, ssoBeta: false, maintenanceMode: false },
  });
});
