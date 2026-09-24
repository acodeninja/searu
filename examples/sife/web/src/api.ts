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
