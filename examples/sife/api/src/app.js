import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { existsSync } from 'node:fs';
import express from 'express';
import cookieParser from 'cookie-parser';
import { config } from './config.js';
import { apiRouter } from './routes/index.js';
import { errorHandler } from './middleware/errors.js';

const here = dirname(fileURLToPath(import.meta.url));

export const createApp = () => {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());

  app.use('/api', apiRouter);

  const publicDir = resolve(here, '..', config.publicDir);
  if (existsSync(publicDir)) {
    app.use(express.static(publicDir));
    app.get(/^(?!\/(api|rest)\b).*/, (req, res, next) => {
      const index = join(publicDir, 'index.html');
      if (existsSync(index)) {
        res.sendFile(index);
      } else {
        next();
      }
    });
  }

  app.use(errorHandler);
  return app;
};
