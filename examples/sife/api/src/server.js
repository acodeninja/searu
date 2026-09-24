import { createApp } from './app.js';
import { config } from './config.js';
import { migrate } from './db/migrate.js';

const start = async () => {
  await migrate();
  const app = createApp();
  app.listen(config.port, () => {
    console.log(`Sife API listening on port ${config.port}`);
  });
};

start().catch((err) => {
  console.error('Failed to start Sife API', err);
  process.exit(1);
});
