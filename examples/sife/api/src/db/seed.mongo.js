import { connectMongo } from './mongo.js';

const articles = [
  {
    slug: 'getting-started',
    title: 'Getting started with Sife',
    body: 'Create a status page, add components, and invite your support agents. This guide walks through the first ten minutes.',
    tags: ['onboarding', 'status-page'],
    published: true,
  },
  {
    slug: 'rest-api-authentication',
    title: 'Authenticating against the REST API',
    body: 'POST your email and password to /rest/user/login to receive a bearer token, then send it as an Authorization header on subsequent calls.',
    tags: ['api', 'authentication'],
    published: true,
  },
  {
    slug: 'incident-templates',
    title: 'Reusable incident templates',
    body: 'Draft incident updates ahead of time so your team can post consistent, calm communications during an outage.',
    tags: ['incidents', 'best-practice'],
    published: true,
  },
  {
    slug: 'internal-runbook',
    title: 'Internal runbook: rotating the signing key',
    body: 'Operators only. The API signing key lives in the JWT_SECRET environment variable and must be rotated quarterly.',
    tags: ['internal', 'security'],
    published: false,
  },
];

const subscribers = [
  { email: 'watch@northwind.example', components: ['REST API', 'Ticketing'], verified: true },
  { email: 'status@globex.example', components: ['REST API'], verified: true },
  { email: 'sre@initech.example', components: ['Dashboard', 'File attachments'], verified: false },
];

export const seedMongo = async () => {
  const db = await connectMongo();
  const kb = db.collection('kb_articles');
  if ((await kb.estimatedDocumentCount()) === 0) {
    await kb.insertMany(articles);
  }
  const subs = db.collection('subscribers');
  if ((await subs.estimatedDocumentCount()) === 0) {
    await subs.insertMany(subscribers);
  }
};
