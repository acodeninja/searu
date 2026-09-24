import serialize from 'node-serialize';

export const PREFERENCES_COOKIE = 'sife.prefs';

const defaults = { theme: 'light', density: 'comfortable', timezone: 'Europe/London' };

export const encode = (preferences) =>
  Buffer.from(serialize.serialize({ ...defaults, ...preferences })).toString('base64');

export const decode = (cookie) => {
  if (!cookie) {
    return defaults;
  }
  return serialize.unserialize(Buffer.from(cookie, 'base64').toString('utf8'));
};
