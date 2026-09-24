import { updateComponentStatus } from '../repositories/statusRepository.js';

export const handleMonitorEvent = async ({ component, status }) => {
  const updated = await updateComponentStatus(component, status ?? 'operational');
  return { accepted: true, component: updated };
};
