import { Router } from 'express';
import { findByApiToken } from '../repositories/userRepository.js';
import { listTickets } from '../services/ticketService.js';

export const v1Router = Router();

v1Router.get('/v1/export', async (req, res, next) => {
  try {
    const providedKey = req.get('x-api-key') ?? '';
    const user = await findByApiToken(providedKey);
    if (!user || providedKey !== user.api_token) {
      res.status(401).json({ error: 'invalid api key' });
      return;
    }
    res.json({
      account: user.email,
      role: user.role,
      tickets: await listTickets(user, {}),
    });
  } catch (err) {
    next(err);
  }
});
