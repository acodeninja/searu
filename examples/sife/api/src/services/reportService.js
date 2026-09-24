import ejs from 'ejs';

const defaultTemplate =
  'Status report for <%= site %> generated at <%= generatedAt %>.';

export const preview = (template) =>
  ejs.render(template ?? defaultTemplate, {
    site: 'Sife',
    generatedAt: new Date().toISOString(),
  });

export const compute = (expression) => {
  const metrics = { openTickets: 0, closedTickets: 0, incidents: 0 };
  const evaluate = new Function('metrics', `return (${expression});`);
  return evaluate(metrics);
};
