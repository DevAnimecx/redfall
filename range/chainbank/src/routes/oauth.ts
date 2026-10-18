import { Router } from 'express';
import pool from '../db';
import { newSessionToken } from '../auth/tokens';

const router = Router();

/**
 * CHN-06, step B — the access token travels in the query string.
 *
 * The consent step redirects to `redirect_uri` with the token appended, which is
 * what makes the open redirect in `redirect.ts` worth chaining: the redirect
 * target receives a live session token. The token is inserted into `sessions`,
 * so it works immediately at `/api/me`.
 */
router.get('/authorize', async (req, res) => {
  const username = String(req.query.username || '');
  const redirectUri = String(req.query.redirect_uri || '/');
  const { rows } = await pool.query(
    `SELECT id, username, role FROM users WHERE username = $1`,
    [username],
  );
  const user = rows[0];
  if (!user) {
    res.status(404).json({ error: 'no_such_user' });
    return;
  }
  const token = newSessionToken();
  await pool.query(`INSERT INTO sessions (user_id, token) VALUES ($1, $2)`, [user.id, token]);
  await pool.query(
    `INSERT INTO audit_log (actor, action, detail) VALUES ($1, 'oauth_token_issued', $2)`,
    [username, redirectUri],
  );
  const separator = redirectUri.includes('?') ? '&' : '?';
  res.redirect(302, `${redirectUri}${separator}access_token=${token}&token_type=Bearer`);
});

export default router;
