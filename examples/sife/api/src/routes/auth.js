import { Router } from 'express';
import { login } from '../services/authService.js';
import { performReset, requestReset } from '../services/recoveryService.js';
import { clearSession, issueSession } from '../auth/session.js';

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

authRouter.post('/user/login', async (req, res, next) => {
  try {
    const { email, password } = req.body ?? {};
    const { user, token } = await login(email, password);
    issueSession(res, user.id);
    res.json({
      authentication: {
        token,
        bid: user.id,
        umail: user.email,
        role: user.role,
      },
    });
  } catch (err) {
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
