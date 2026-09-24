import { Router } from 'express';
import { register } from '../services/authService.js';
import { issueSession } from '../auth/session.js';

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
