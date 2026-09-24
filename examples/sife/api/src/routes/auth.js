import { Router } from 'express';
import { login } from '../services/authService.js';
import { clearSession, issueSession } from '../auth/session.js';

export const authRouter = Router();

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
