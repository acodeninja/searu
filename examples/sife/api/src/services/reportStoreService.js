import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { uploadsDir } from './attachmentService.js';

export const saveReport = async (name, content) => {
  const target = join(uploadsDir, name);
  await writeFile(target, content ?? '');
  return { saved: true, name, url: `/uploads/${name}` };
};
