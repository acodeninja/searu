import { getStatusPage } from './statusService.js';

const updateLine = (update) => `${update.status}: ${update.body}`;

const item = (incident) => `
    <item>
      <title>${incident.title}</title>
      <description>${incident.body}</description>
      <category>${incident.severity}</category>
      <content:encoded>${incident.updates.map(updateLine).join(' | ')}</content:encoded>
      <guid>incident-${incident.id}</guid>
    </item>`;

export const incidentFeed = async () => {
  const { incidents } = await getStatusPage();
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Sife status</title>
    <link>http://localhost:8080/status</link>
    <description>Latest incidents and maintenance for Sife</description>${incidents.map(item).join('')}
  </channel>
</rss>`;
};
