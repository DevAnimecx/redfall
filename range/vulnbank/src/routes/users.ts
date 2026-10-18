import { Router, Request, Response } from 'express';
import pool from '../db';
import { requireAuth, AuthedRequest } from '../middleware/jwt';

const router = Router();

// NOTE on ordering: `/` and `/search` are declared before `/:id` so that Express
// does not treat "search" as an :id parameter.

// VULN-009: the `limit` query parameter is unbounded, so `?limit=1000000` dumps
// the whole table in one response (CWE-770).
router.get('/', requireAuth, async (req: Request, res: Response) => {
  const limitRaw = req.query.limit;
  const limit = limitRaw === undefined ? 25 : Number(limitRaw);
  if (!Number.isFinite(limit) || limit < 0) {
    res.status(400).json({ error: 'invalid_limit' });
    return;
  }
  try {
    const result = await pool.query(
      `SELECT id, username, email, role, balance FROM users ORDER BY id LIMIT $1`,
      [limit],
    );
    res.status(200).json({ count: result.rowCount, limit, users: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'list_failed', detail: (err as Error).message });
  }
});

// VULN-010: `q` is echoed back into an HTML body without encoding, so a script
// payload is reflected and executed in the victim's browser (CWE-79).
router.get('/search', requireAuth, async (req: Request, res: Response) => {
  const q = typeof req.query.q === 'string' ? req.query.q : '';
  if (!q) {
    res.status(400).send('<html><body>query parameter "q" is required</body></html>');
    return;
  }
  try {
    const result = await pool.query(
      `SELECT id, username FROM users WHERE username ILIKE $1 ORDER BY id LIMIT 20`,
      [`%${q}%`],
    );
    const rows = result.rows.map((r) => `<li>${r.id} — ${r.username}</li>`).join('');
    res
      .status(200)
      .type('html')
      .send(
        `<html><body><h1>Search results for: ${q}</h1><ul>${rows}</ul>` +
          `<p>${result.rowCount} match(es)</p></body></html>`,
      );
  } catch (err) {
    res.status(500).send(`<html><body>search failed: ${(err as Error).message}</body></html>`);
  }
});

// VULN-008: the caller supplies :id and the handler never compares it against the
// authenticated identity, so any token can read any account (CWE-639).
router.get('/:id', requireAuth, (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: 'invalid_id' });
    return;
  }
  pool
    .query(
      `SELECT u.id, u.username, u.email, u.role, u.balance, u.kyc_complete, u.created_at,
              p.display_name, p.bio, p.website
       FROM users u LEFT JOIN profiles p ON p.user_id = u.id
       WHERE u.id = $1`,
      [id],
    )
    .then((result) => {
      if (result.rowCount === 0) {
        res.status(404).json({ error: 'user_not_found' });
        return;
      }
      res.status(200).json({ user: result.rows[0] });
    })
    .catch((err) => res.status(500).json({ error: 'lookup_failed', detail: (err as Error).message }));
});

export default router;
