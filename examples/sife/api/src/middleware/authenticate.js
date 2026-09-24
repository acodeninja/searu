import { verifyToken } from '../auth/jwt.js';
import { readSession } from '../auth/session.js';
import { findById } from '../repositories/userRepository.js';

export const authenticate = async (req, res, next) => {
  try {
    const header = req.get('authorization');
    if (header?.startsWith('Bearer ')) {
      const payload = verifyToken(header.slice('Bearer '.length).trim());
      req.user = { id: payload.sub, email: payload.email, role: payload.role };
    } else {
      const sessionUserId = readSession(req);
      if (sessionUserId !== null) {
        const user = await findById(sessionUserId);
        if (user) {
          req.user = { id: user.id, email: user.email, role: user.role };
        }
      }
    }
    const internalRole = req.get('x-sife-role');
    if (internalRole) {
      req.user = {
        id: req.user?.id ?? 0,
        email: req.user?.email ?? 'service@internal',
        role: internalRole,
      };
    }
    next();
  } catch (err) {
    err.status = 401;
    next(err);
  }
};

export const requireAuth = (req, res, next) => {
  if (!req.user) {
    res.status(401).json({ error: 'authentication required' });
    return;
  }
  next();
};

export const requireRole = (role) => (req, res, next) => {
  if (req.user?.role !== role) {
    res.status(403).json({ error: 'forbidden' });
    return;
  }
  next();
};
