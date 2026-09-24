import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { existsSync } from 'node:fs';
import express from 'express';
import cookieParser from 'cookie-parser';
import fileUpload from 'express-fileupload';
import serveIndex from 'serve-index';
import { config } from './config.js';
import { apiRouter } from './routes/index.js';
import { authRouter } from './routes/auth.js';
import { authenticate } from './middleware/authenticate.js';
import { errorHandler } from './middleware/errors.js';

const here = dirname(fileURLToPath(import.meta.url));

export const createApp = () => {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(express.text({ type: ['application/xml', 'text/xml'] }));
  app.use(cookieParser());
  app.use(fileUpload());
  app.use(authenticate);

  app.use('/rest', authRouter);
  app.use('/api', apiRouter);

  const uploadsDir = resolve(here, '..', 'uploads');
  const downloadsDir = resolve(here, '..', 'downloads');
  app.use('/uploads', express.static(uploadsDir), serveIndex(uploadsDir, { icons: true }));
  app.use(
    '/downloads',
    express.static(downloadsDir, { dotfiles: 'allow' }),
    serveIndex(downloadsDir, { icons: true }),
  );

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
