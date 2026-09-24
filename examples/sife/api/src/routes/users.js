import { Router } from 'express';
import { register } from '../services/authService.js';
import { issueSession } from '../auth/session.js';
import { requireAuth, requireRole } from '../middleware/authenticate.js';
import * as userService from '../services/userService.js';
import { changePassword, setQuestion } from '../services/recoveryService.js';

export const usersRouter = Router();

usersRouter.post('/users/register', async (req, res, next) => {
  try {
    const { user, token } = await register(req.body ?? {});
    issueSession(res, user.id);
    res.status(201).json({
      user,
      authentication: { token, bid: user.id, umail: user.email, role: user.role },
    });
  } catch (err) {
    next(err);
  }
});

usersRouter.get('/users', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    res.json(await userService.listUsers());
  } catch (err) {
    next(err);
  }
});

usersRouter.get('/users/:id', requireAuth, async (req, res, next) => {
  try {
    res.json(await userService.getUser(Number.parseInt(req.params.id, 10)));
  } catch (err) {
    next(err);
  }
});

usersRouter.put('/users/:id/password', requireAuth, async (req, res, next) => {
  try {
    const newPassword = (req.body?.newPassword ?? '').toString();
    res.json(await changePassword(Number.parseInt(req.params.id, 10), newPassword));
  } catch (err) {
    next(err);
  }
});

usersRouter.post('/users/:id/security-question', requireAuth, async (req, res, next) => {
  try {
    const { question, answer } = req.body ?? {};
    await setQuestion(Number.parseInt(req.params.id, 10), (question ?? '').toString(), (answer ?? '').toString());
    res.json({ updated: true });
  } catch (err) {
    next(err);
  }
});
