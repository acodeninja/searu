import { Router } from 'express';
import { requireAuth } from '../middleware/authenticate.js';
import * as service from '../services/attachmentService.js';

export const attachmentsRouter = Router();

attachmentsRouter.post('/tickets/:id/attachments', requireAuth, async (req, res, next) => {
  try {
    const file = req.files?.file;
    if (!file) {
      res.status(400).json({ error: 'no file provided' });
      return;
    }
    const saved = await service.saveUpload(Number.parseInt(req.params.id, 10), file);
    res.status(201).json({
      id: saved.id,
      filename: saved.filename,
      url: `/uploads/${saved.filename}`,
    });
  } catch (err) {
    next(err);
  }
});

attachmentsRouter.get('/tickets/:id/attachments', requireAuth, async (req, res, next) => {
  try {
    res.json(await service.listForTicket(Number.parseInt(req.params.id, 10)));
  } catch (err) {
    next(err);
  }
});

attachmentsRouter.get('/attachments', async (req, res, next) => {
  try {
    const content = await service.readByPath(req.query.path ?? '');
    res.type('application/octet-stream').send(content);
  } catch (err) {
    next(err);
  }
});

attachmentsRouter.get('/attachments/:id', async (req, res, next) => {
  try {
    const attachment = await service.getById(Number.parseInt(req.params.id, 10));
    res.download(attachment.stored_path, attachment.filename);
  } catch (err) {
    next(err);
  }
});
