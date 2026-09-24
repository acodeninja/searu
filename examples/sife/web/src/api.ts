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
const ROLE_KEY = 'sife.role';

export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (token: string) => localStorage.setItem(TOKEN_KEY, token);
export const clearToken = () => localStorage.removeItem(TOKEN_KEY);

export const getRole = () => localStorage.getItem(ROLE_KEY);
export const setRole = (role: string) => localStorage.setItem(ROLE_KEY, role);

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
  setRole(body.authentication.role);
  return body.authentication;
};

export const getAdminSettings = () => request('/api/admin/settings');

export const whoami = (): Promise<{ user: CurrentUser }> => request('/rest/user/whoami');

export const logout = async () => {
  await request('/rest/user/logout', { method: 'POST' });
  clearToken();
};

export const register = async (fields: {
  email: string;
  password: string;
  full_name: string;
  organisation?: string;
}) => {
  const body = await request('/api/users/register', {
    method: 'POST',
    body: JSON.stringify(fields),
  });
  setToken(body.authentication.token);
  return body;
};

export const requestReset = (email: string) =>
  request('/rest/user/reset-request', { method: 'POST', body: JSON.stringify({ email }) });

export const performReset = (token: string, newPassword: string) =>
  request('/rest/user/reset', { method: 'POST', body: JSON.stringify({ token, newPassword }) });

export const securityRecover = (email: string, answer: string): Promise<{ token: string }> =>
  request('/rest/user/security-recover', {
    method: 'POST',
    body: JSON.stringify({ email, answer }),
  });

export const subscribeStatus = (email: string, components: string[]) =>
  request('/api/subscribers', { method: 'POST', body: JSON.stringify({ email, components }) });

export type Plan = { plan: string; seats: number };

export const getBilling = (): Promise<Plan> => request('/api/billing');

export const subscribePlan = (plan: string, seats: number, amount: number) =>
  request('/api/billing/subscribe', {
    method: 'POST',
    body: JSON.stringify({ plan, seats, amount }),
  });

export const requestCredit = (amount: number): Promise<{ balance: number }> =>
  request('/api/billing/refund', { method: 'POST', body: JSON.stringify({ amount }) });

export const shareTicket = (id: number): Promise<{ token: string; url: string }> =>
  request(`/api/tickets/${id}/share`, { method: 'POST' });

export const redeemCode = (code: string): Promise<{ balance: number; value: number }> =>
  request('/api/billing/redeem', { method: 'POST', body: JSON.stringify({ code }) });

export const inviteTeammate = (email: string, name: string) =>
  request('/api/team/invite', { method: 'POST', body: JSON.stringify({ email, name }) });

export type Article = {
  slug: string;
  title: string;
  body: string;
  tags: string[];
  published: boolean;
};

export const getArticles = (): Promise<Article[]> => request('/api/kb');

export const searchArticles = (term: string): Promise<Article[]> =>
  request('/api/kb/search', {
    method: 'POST',
    body: JSON.stringify({ title: { $regex: term, $options: 'i' }, published: true }),
  });

export type Reaction = { emoji: string; count: number };
export type ReactionSummary = {
  incident: { id: number; title: string } | null;
  total: number;
  reactions: Reaction[];
};

export const getReactions = (incidentId: number): Promise<ReactionSummary> =>
  request(`/api/incidents/${incidentId}/reactions`);

export const postReaction = (incidentId: number, emoji: string): Promise<ReactionSummary> =>
  request(`/api/incidents/${incidentId}/reactions`, {
    method: 'POST',
    body: JSON.stringify({ emoji }),
  });

export type IncidentSearchHit = {
  id: number;
  title: string;
  body: string;
  severity: string;
  status: string;
};

export const searchIncidents = (q: string): Promise<IncidentSearchHit[]> =>
  request(`/api/incidents/search?q=${encodeURIComponent(q)}`);

export type Ticket = {
  id: number;
  user_id: number;
  subject: string;
  body?: string;
  status: string;
  priority: string;
  is_public: boolean;
  created_at: string;
  requester?: string;
};

export type Comment = {
  id: number;
  ticket_id: number;
  author_id: number | null;
  author_name: string | null;
  body: string;
  body_html: string;
  created_at: string;
};

export const getTickets = (search?: string): Promise<Ticket[]> =>
  request(`/api/tickets${search ? `?search=${encodeURIComponent(search)}` : ''}`);

export const getTicket = (id: number): Promise<Ticket> => request(`/api/tickets/${id}`);

export const getComments = (id: number): Promise<Comment[]> =>
  request(`/api/tickets/${id}/comments`);

export const postComment = (id: number, body: string): Promise<Comment> =>
  request(`/api/tickets/${id}/comments`, { method: 'POST', body: JSON.stringify({ body }) });

export type Attachment = {
  id: number;
  ticket_id: number;
  filename: string;
  content_type: string | null;
  created_at: string;
};

export const getAttachments = (id: number): Promise<Attachment[]> =>
  request(`/api/tickets/${id}/attachments`);

export const uploadAttachment = async (id: number, file: File) => {
  const form = new FormData();
  form.append('file', file);
  const response = await fetch(`/api/tickets/${id}/attachments`, {
    method: 'POST',
    credentials: 'include',
    headers: { ...authHeaders() },
    body: form,
  });
  return asJson(response);
};
