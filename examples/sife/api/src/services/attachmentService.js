import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import * as attachments from '../repositories/attachmentRepository.js';

const here = dirname(fileURLToPath(import.meta.url));
export const uploadsDir = resolve(here, '..', '..', 'uploads');

export const saveUpload = async (ticketId, file) => {
  const storedPath = join(uploadsDir, file.name);
  await file.mv(storedPath);
  return attachments.create({
    ticketId,
    filename: file.name,
    storedPath,
    contentType: file.mimetype,
  });
};

export const readByPath = (relativePath) => readFile(join(uploadsDir, relativePath));

export const getById = async (id) => {
  const attachment = await attachments.findById(id);
  if (!attachment) {
    const err = new Error('Attachment not found');
    err.status = 404;
    throw err;
  }
  return attachment;
};

export const listForTicket = (ticketId) => attachments.listForTicket(ticketId);
