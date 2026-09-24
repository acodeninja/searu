export const SESSION_COOKIE = 'sife.sid';

export const issueSession = (res, userId) => {
  const value = Buffer.from(`uid:${userId}`).toString('base64');
  res.cookie(SESSION_COOKIE, value);
};

export const readSession = (req) => {
  const raw = req.cookies?.[SESSION_COOKIE];
  if (!raw) {
    return null;
  }
  const decoded = Buffer.from(raw, 'base64').toString('utf8');
  const match = decoded.match(/^uid:(\d+)$/);
  return match ? Number.parseInt(match[1], 10) : null;
};

export const clearSession = (res) => {
  res.clearCookie(SESSION_COOKIE);
};
