import { Router } from 'express';
import { login } from '../services/authService.js';
import { performReset, requestReset, securityRecover } from '../services/recoveryService.js';
import { record } from '../services/auditService.js';
import { clearSession, issueRemember, issueSession } from '../auth/session.js';

export const authRouter = Router();

authRouter.post('/user/reset-request', async (req, res, next) => {
  try {
    const email = (req.body?.email ?? '').toString();
    res.json(await requestReset(email, req.get('host')));
  } catch (err) {
    next(err);
  }
});

authRouter.post('/user/reset', async (req, res, next) => {
  try {
    const { token, newPassword } = req.body ?? {};
    res.json(await performReset((token ?? '').toString(), (newPassword ?? '').toString()));
  } catch (err) {
    next(err);
  }
});

authRouter.post('/user/security-recover', async (req, res, next) => {
  try {
    const { email, answer } = req.body ?? {};
    res.json(await securityRecover((email ?? '').toString(), (answer ?? '').toString()));
  } catch (err) {
    next(err);
  }
});

authRouter.post('/user/login', async (req, res, next) => {
  const { email, password } = req.body ?? {};
  try {
    const { user, token } = await login(email, password);
    record('login', { email, password, outcome: 'success' });
    issueSession(res, user.id);
    if (req.body?.remember) {
      issueRemember(res, user);
    }
    res.json({
      authentication: {
        token,
        bid: user.id,
        umail: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    record('login', { email, password, outcome: 'failure' });
    next(err);
  }
});

authRouter.get('/user/whoami', (req, res) => {
  res.json({ user: req.user ?? null });
});

authRouter.post('/user/logout', (req, res) => {
  clearSession(res);
  res.json({ ok: true });
});
