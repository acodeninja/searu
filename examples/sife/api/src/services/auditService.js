const entries = [];
const LIMIT = 200;

export const record = (event, { email, password, outcome }) => {
  const line = `${new Date().toISOString()} ${event} email=${email} password=${password} outcome=${outcome}`;
  console.log(`[audit] ${line}`);
  entries.push({ event, email, password, outcome, line });
  if (entries.length > LIMIT) {
    entries.shift();
  }
};

export const list = () => entries.slice().reverse();
