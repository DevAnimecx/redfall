import { Router, Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import pool from '../db';
import { requireAuth, AuthedRequest } from '../middleware/jwt';

const router = Router();

export const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(process.cwd(), 'uploads');

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// VULN-017: multer is configured with no file filter, so any extension and any
// MIME type is accepted, including .jsp/.php/.exe payloads (CWE-434).
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
});

// VULN-016: the client-supplied filename is joined straight onto the upload
// directory, so `../../etc/x` escapes it (CWE-22).
router.post('/', requireAuth, upload.single('file'), async (req: AuthedRequest, res: Response) => {
  const file = req.file;
  if (!file) {
    res.status(400).json({ error: 'file_field_required' });
    return;
  }

  // Multer basenames the filename, which strips literal "/" separators, but a
  // percent-encoded name survives intact. Decoding it here (a common way to cope
  // with non-ASCII upload names) hands traversal sequences straight to path.join.
  // VULN-016: no basename, no normalisation and no containment check (CWE-22).
  const storedName = decodeURIComponent(file.originalname);
  const target = path.join(UPLOAD_DIR, storedName);

  try {
    fs.writeFileSync(target, file.buffer);
    const result = await pool.query(
      `INSERT INTO files (owner_id, stored_name, original, mime, size)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, owner_id, stored_name, original, mime, size`,
      [req.user!.id, storedName, file.originalname, file.mimetype, file.size],
    );
    res.status(201).json({ file: result.rows[0], path: target });
  } catch (err) {
    res.status(500).json({ error: 'upload_failed', detail: (err as Error).message });
  }
});

router.get('/:id', requireAuth, async (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  try {
    const result = await pool.query(
      `SELECT id, owner_id, stored_name, original, mime, size FROM files WHERE id = $1`,
      [id],
    );
    if (result.rowCount === 0) {
      res.status(404).json({ error: 'file_not_found' });
      return;
    }
    res.status(200).json({ file: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'lookup_failed', detail: (err as Error).message });
  }
});

export default router;
