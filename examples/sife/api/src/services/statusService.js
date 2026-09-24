import {
  listComponents,
  listPublicIncidents,
  listUpdatesFor,
} from '../repositories/statusRepository.js';

const overallStatus = (components) => {
  if (components.some((c) => c.status === 'major_outage')) {
    return 'major_outage';
  }
  if (components.some((c) => c.status === 'partial_outage')) {
    return 'partial_outage';
  }
  if (components.some((c) => c.status === 'degraded_performance')) {
    return 'degraded_performance';
  }
  return 'operational';
};

export const getStatusPage = async () => {
  const [components, incidents] = await Promise.all([
    listComponents(),
    listPublicIncidents(),
  ]);
  const updates = await listUpdatesFor(incidents.map((i) => i.id));
  const updatesByIncident = new Map();
  for (const update of updates) {
    const list = updatesByIncident.get(update.incident_id) ?? [];
    list.push({ status: update.status, body: update.body, createdAt: update.created_at });
    updatesByIncident.set(update.incident_id, list);
  }
  return {
    status: overallStatus(components),
    components,
    incidents: incidents.map((incident) => ({
      ...incident,
      updates: updatesByIncident.get(incident.id) ?? [],
    })),
  };
};
