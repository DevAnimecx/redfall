import { Router } from 'express';
import fetch from 'node-fetch';
import pool from '../db';
import { requireAuth } from '../middleware/auth';

const router = Router();

/**
 * CHN-04, step A — server-side request forgery.
 *
 * The URL comes straight from the request with no allow-list, so the caller
 * decides where the server connects. The interesting destination is not the
 * public internet: it is the internal metadata service, which the app trusts
 * precisely because it is not reachable from outside.
 */
router.post('/', requireAuth, async (req, res) => {
  const url = String(req.body?.url || '');
  if (!url) {
    res.status(400).json({ error: 'url_required' });
    return;
  }
  try {
    const upstream = await fetch(url, { timeout: 5000 });
    const body = await upstream.text();
    await pool.query(
      `INSERT INTO audit_log (actor, action, detail) VALUES ('system', 'preview_fetched', $1)`,
      [url],
    );
    res.json({ url, status: upstream.status, body: body.slice(0, 4000) });
  } catch (err) {
    res.status(502).json({ error: 'fetch_failed', url, detail: (err as Error).message });
  }
});

export default router;
