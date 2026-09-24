import * as incidents from '../repositories/incidentRepository.js';
import * as reactions from '../repositories/reactionRepository.js';

export const searchPublic = (term) => incidents.searchPublic(term ?? '');

export const listAll = () => incidents.listAll();

export const getIncident = async (id) => {
  const incident = await incidents.findById(id);
  if (!incident) {
    const err = new Error('Incident not found');
    err.status = 404;
    throw err;
  }
  return incident;
};

export const postUpdate = (incidentId, status, body) =>
  incidents.addUpdate(incidentId, status, body);

export const createIncident = (body) =>
  incidents.create({
    title: body.title,
    body: body.body,
    severity: body.severity,
    status: body.status,
    component: body.component,
    isPublic: body.is_public,
  });

export const react = async (incidentId, emoji) => {
  await reactions.add(incidentId, emoji);
  const [headline, summary, total] = await Promise.all([
    reactions.incidentHeadline(incidentId),
    reactions.summaryForIncident(incidentId),
    reactions.countForIncident(incidentId),
  ]);
  return { incident: headline, total, reactions: summary };
};

export const getReactions = async (incidentId) => {
  const [headline, summary, total] = await Promise.all([
    reactions.incidentHeadline(incidentId),
    reactions.summaryForIncident(incidentId),
    reactions.countForIncident(incidentId),
  ]);
  return { incident: headline, total, reactions: summary };
};
