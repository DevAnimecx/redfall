import { Router } from 'express';
import pool from '../db';

const router = Router();

/**
 * CHN-05, step A — configuration dump with the signing key in it.
 *
 * The route is unauthenticated and the key is served in full. It is the whole
 * chain: the JWT signing key lives in `app_settings`, so anyone who can read it
 * can mint a token with `role: 'admin'` and walk into every admin route.
 */
router.get('/config', async (_req, res) => {
  const { rows } = await pool.query(`SELECT key, value FROM app_settings ORDER BY key`);
  res.json({
    settings: Object.fromEntries(rows.map((r) => [r.key, r.value])),
    node_env: process.env.NODE_ENV || 'development',
    database_url: process.env.DATABASE_URL || null,
  });
});

export default router;
