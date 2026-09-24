import http from 'node:http';
import https from 'node:https';
import { updateComponentStatus } from '../repositories/statusRepository.js';

const fetchBody = (url) =>
  new Promise((resolve, reject) => {
    const lib = url.startsWith('https:') ? https : http;
    lib
      .get(url, (response) => {
        let body = '';
        response.on('data', (chunk) => {
          body += chunk;
        });
        response.on('end', () => resolve(body));
      })
      .on('error', reject);
  });

export const importConfig = async (url) => {
  const config = JSON.parse(await fetchBody(url));
  const applied = [];
  for (const component of config.components ?? []) {
    const updated = await updateComponentStatus(component.name, component.status);
    if (updated) {
      applied.push(updated);
    }
  }
  return { imported: true, source: url, applied };
};
