import { Router, Request, Response } from 'express';
import pool from '../db';
import { requireAuth, AuthedRequest } from '../middleware/jwt';

const router = Router();

// VULN-011: `bio` is stored verbatim and rendered into HTML without escaping, so
// a payload planted via PUT survives for every later viewer (CWE-79).
router.put('/:id/profile', requireAuth, async (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  const body = (req.body || {}) as { display_name?: unknown; bio?: unknown; website?: unknown };
  const displayName = typeof body.display_name === 'string' ? body.display_name : '';
  const bio = typeof body.bio === 'string' ? body.bio : '';
  const website = typeof body.website === 'string' ? body.website : '';

  try {
    await pool.query(
      `INSERT INTO profiles (user_id, display_name, bio, website, updated_at)
       VALUES ($1, $2, $3, $4, now())
       ON CONFLICT (user_id) DO UPDATE
       SET display_name = EXCLUDED.display_name, bio = EXCLUDED.bio,
           website = EXCLUDED.website, updated_at = now()`,
      [id, displayName, bio, website],
    );
    res.status(200).json({ ok: true, user_id: id });
  } catch (err) {
    res.status(500).json({ error: 'profile_update_failed', detail: (err as Error).message });
  }
});

// VULN-012: raw driver errors (including SQL state and query text) are returned to
// the caller, leaking schema details (CWE-209).
router.get('/:id/profile', requireAuth, async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  try {
    const result = await pool.query(
      `SELECT p.user_id, u.username, p.display_name, p.bio, p.website, p.updated_at
       FROM profiles p JOIN users u ON u.id = p.user_id
       WHERE p.user_id = $1`,
      [id],
    );
    if (result.rowCount === 0) {
      res.status(404).json({ error: 'profile_not_found' });
      return;
    }
    // Rendered as HTML: the stored bio is emitted unescaped (VULN-011).
    const p = result.rows[0];
    res
      .status(200)
      .type('html')
      .send(
        `<html><body><h2>${p.username}</h2><div class="bio">${p.bio}</div>` +
          `<a href="${p.website}">${p.display_name}</a></body></html>`,
      );
  } catch (err) {
    const e = err as { message: string; stack?: string; code?: string; query?: string };
    res.status(500).json({
      error: 'profile_lookup_failed',
      message: e.message,
      code: e.code,
      stack: e.stack,
      query: e.query,
    });
  }
});

export default router;
