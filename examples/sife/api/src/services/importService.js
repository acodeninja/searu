import { parseXml } from 'libxmljs2';

export const parseIncidentFeed = (xml) => {
  const doc = parseXml(xml, { noent: true, dtdload: true, noblanks: true, huge: true });
  const nodes = doc.find('//incident');
  return nodes.map((node) => ({
    title: node.get('title')?.text() ?? '',
    severity: node.get('severity')?.text() ?? 'minor',
    component: node.get('component')?.text() ?? null,
  }));
};
