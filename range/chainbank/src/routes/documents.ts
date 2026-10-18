import { Router } from 'express';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import pool from '../db';
import { requireAuth, AuthedRequest } from '../middleware/auth';

const router = Router();

export const PLUGIN_DIR = process.env.CHAINBANK_PLUGIN_DIR || path.join(process.cwd(), 'plugins');
const UPLOAD_DIR = process.env.CHAINBANK_UPLOAD_DIR || path.join(process.cwd(), 'uploads');

for (const dir of [PLUGIN_DIR, UPLOAD_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

/**
 * CHN-03, step A — upload that keeps whatever filename it is given.
 *
 * The destination is the plugin directory, and multer's default filename
 * handling preserves the client-supplied extension. A `.js` upload is therefore
 * a file the plugin loader in `plugins.ts` will execute on the next reload.
 */
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, PLUGIN_DIR),
    filename: (_req, file, cb) => cb(null, path.basename(file.originalname)),
  }),
  limits: { fileSize: 1024 * 256 },
});

router.post('/', requireAuth, upload.single('file'), async (req: AuthedRequest, res) => {
  if (!req.file) {
    res.status(400).json({ error: 'file_required' });
    return;
  }
  const storedPath = path.join(PLUGIN_DIR, req.file.filename);
  await pool.query(
    `INSERT INTO documents (filename, stored_path, uploaded_by) VALUES ($1, $2, $3)`,
    [req.file.filename, storedPath, req.user?.username || 'anonymous'],
  );
  res.status(201).json({
    document: { filename: req.file.filename, stored_path: storedPath, size: req.file.size },
  });
});

router.get('/', requireAuth, async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, filename, stored_path, uploaded_by FROM documents ORDER BY id`,
  );
  res.json({ documents: rows });
});

export default router;
