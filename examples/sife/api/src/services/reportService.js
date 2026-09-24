import ejs from 'ejs';

const defaultTemplate =
  'Status report for <%= site %> generated at <%= generatedAt %>.';

export const preview = (template) =>
  ejs.render(template ?? defaultTemplate, {
    site: 'Sife',
    generatedAt: new Date().toISOString(),
  });
