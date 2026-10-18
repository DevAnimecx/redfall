import { Router, Request, Response } from 'express';
import serialize from 'node-serialize';
import { requireAuth, AuthedRequest } from '../middleware/jwt';

const router = Router();

interface ImportBody {
  batch?: unknown;
}

// VULN-031: the request body is handed to node-serialize's unserialize(), which
// evaluates the IIFE wrappers it emits for functions, giving remote code
// execution to any authenticated caller (CWE-502).
router.post('/', requireAuth, (req: AuthedRequest, res: Response) => {
  const body = (req.body || {}) as ImportBody;

  if (!body.batch) {
    res.status(400).json({ error: 'batch is required' });
    return;
  }

  try {
    const payload = typeof body.batch === 'string' ? body.batch : JSON.stringify(body.batch);
    const restored = serialize.unserialize(payload);
    res.status(200).json({ ok: true, imported: restored });
  } catch (err) {
    res.status(400).json({ error: 'import_failed', detail: (err as Error).message });
  }
});

export default router;
