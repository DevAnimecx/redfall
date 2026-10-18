import { Router, Response } from 'express';
import pool from '../db';
import { requireAuth, AuthedRequest } from '../middleware/jwt';

const router = Router();

// VULN-030: a recursive merge that follows `__proto__` keys, so a crafted body
// pollutes Object.prototype for the whole process (CWE-1321).
function merge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  for (const key of Object.keys(source)) {
    const value = (source as Record<string, unknown>)[key];
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const existing = (target as Record<string, unknown>)[key];
      (target as Record<string, unknown>)[key] = merge(
        (existing && typeof existing === 'object' ? existing : {}) as Record<string, unknown>,
        value as Record<string, unknown>,
      );
    } else {
      (target as Record<string, unknown>)[key] = value;
    }
  }
  return target;
}

router.post('/', requireAuth, async (req: AuthedRequest, res: Response) => {
  const incoming = (req.body || {}) as Record<string, unknown>;
  const me = req.user!.id;

  try {
    const current = await pool.query(`SELECT payload FROM settings WHERE owner_id = $1`, [me]);
    const base = (current.rowCount ? (current.rows[0].payload as Record<string, unknown>) : {}) || {};
    const merged = merge(base as Record<string, unknown>, incoming);

    await pool.query(
      `INSERT INTO settings (owner_id, payload, updated_at) VALUES ($1, $2::jsonb, now())
       ON CONFLICT (owner_id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()`,
      [me, JSON.stringify(merged)],
    );

    res.status(200).json({ ok: true, settings: merged });
  } catch (err) {
    res.status(500).json({ error: 'settings_failed', detail: (err as Error).message });
  }
});

router.get('/', requireAuth, async (req: AuthedRequest, res: Response) => {
  try {
    const result = await pool.query(`SELECT payload FROM settings WHERE owner_id = $1`, [req.user!.id]);
    res.status(200).json({ settings: result.rowCount ? result.rows[0].payload : {} });
  } catch (err) {
    res.status(500).json({ error: 'settings_failed', detail: (err as Error).message });
  }
});

export default router;
