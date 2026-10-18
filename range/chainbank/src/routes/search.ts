import { Router } from 'express';
import pool from '../db';

const router = Router();

/**
 * CHN-02, step A — classic string-concatenation SQL injection.
 *
 * The query is built by interpolation so the injection point is unambiguous to a
 * static scanner as well as to a scanner that reaches it at runtime.
 */
router.get('/', async (req, res) => {
  const q = String(req.query.q || '');
  const sql = `SELECT id, username, email, role, balance FROM users
                WHERE username ILIKE '%${q}%' OR email ILIKE '%${q}%'`;
  try {
    const { rows } = await pool.query(sql);
    res.json({ q, count: rows.length, results: rows });
  } catch (err) {
    res.status(500).json({ error: 'query_failed', detail: (err as Error).message, sql });
  }
});

/**
 * CHN-02, step B — login by password hash.
 *
 * Added for the "import users from another branch" feature and never removed. It
 * compares the supplied hash to the stored one instead of hashing the supplied
 * password, so the injection above converts directly into a working admin
 * session: read `password_hash` with the UNION, then post it back here.
 */
router.post('/by-hash', async (req, res) => {
  const { username, password_hash } = req.body || {};
  const { rows } = await pool.query(
    `SELECT id, username, password_hash, role, balance FROM users WHERE username = $1`,
    [username],
  );
  const user = rows[0];
  if (!user || user.password_hash !== String(password_hash || '')) {
    res.status(401).json({ error: 'invalid_credentials' });
    return;
  }
  const { signToken } = await import('../auth/tokens');
  const token = await signToken({ sub: user.id, username: user.username, role: user.role });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

export default router;
