export type Component = {
  id: number;
  name: string;
  status: string;
  position: number;
};

export type IncidentUpdate = {
  status: string;
  body: string;
  createdAt: string;
};

export type Incident = {
  id: number;
  title: string;
  body: string;
  severity: string;
  status: string;
  component: string | null;
  created_at: string;
  updated_at: string;
  updates: IncidentUpdate[];
};

export type StatusPage = {
  status: string;
  components: Component[];
  incidents: Incident[];
};

const asJson = async (response: Response) => {
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body.error ?? `Request failed with ${response.status}`);
  }
  return body;
};

export const getStatus = (): Promise<StatusPage> =>
  fetch('/api/status', { credentials: 'include' }).then(asJson);

const TOKEN_KEY = 'sife.token';

export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (token: string) => localStorage.setItem(TOKEN_KEY, token);
export const clearToken = () => localStorage.removeItem(TOKEN_KEY);

const authHeaders = (): Record<string, string> => {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
};

export const request = async (path: string, init: RequestInit = {}) => {
  const response = await fetch(path, {
    ...init,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...(init.headers ?? {}),
    },
  });
  return asJson(response);
};

export type CurrentUser = { id: number; email: string; role: string } | null;

export const login = async (email: string, password: string) => {
  const body = await request('/rest/user/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  setToken(body.authentication.token);
  return body.authentication;
};

export const whoami = (): Promise<{ user: CurrentUser }> => request('/rest/user/whoami');

export const logout = async () => {
  await request('/rest/user/logout', { method: 'POST' });
  clearToken();
};
