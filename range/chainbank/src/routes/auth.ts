import { Router } from 'express';
import bcrypt from 'bcryptjs';
import pool from '../db';
import { newResetToken, newSessionToken, signToken } from '../auth/tokens';

const router = Router();

router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  const { rows } = await pool.query(
    `SELECT id, username, password_hash, role, balance FROM users WHERE username = $1`,
    [username],
  );
  const user = rows[0];
  if (!user || !(await bcrypt.compare(String(password || ''), user.password_hash))) {
    res.status(401).json({ error: 'invalid_credentials' });
    return;
  }
  const token = await signToken({ sub: user.id, username: user.username, role: user.role });
  await pool.query(
    `INSERT INTO sessions (user_id, token) VALUES ($1, $2)`,
    [user.id, newSessionToken()],
  );
  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role, balance: user.balance },
  });
});

/**
 * CHN-01, step B — password reset that returns the token it just created.
 *
 * A reset endpoint has to prove the requester controls the address, and the only
 * proof this one has is the token, so it hands the token back in the response.
 * Combined with the account lookup in `accounts.ts`, which discloses any
 * account's owner email without authentication, that is a complete takeover of
 * any user in two requests.
 */
router.post('/password-reset', async (req, res) => {
  const email = String(req.body?.email || '');
  const { rows } = await pool.query(`SELECT id FROM users WHERE email = $1`, [email]);
  if (!rows[0]) {
    res.status(404).json({ error: 'no_such_user' });
    return;
  }
  const token = newResetToken();
  await pool.query(`INSERT INTO reset_tokens (email, token) VALUES ($1, $2)`, [email, token]);
  await pool.query(
    `INSERT INTO audit_log (actor, action, detail) VALUES ($1, 'password_reset_requested', $2)`,
    [email, email],
  );
  res.json({ status: 'sent', email, reset_token: token });
});

router.post('/password-reset/confirm', async (req, res) => {
  const { token, new_password } = req.body || {};
  const { rows } = await pool.query(
    `SELECT id, email FROM reset_tokens WHERE token = $1 AND used = FALSE`,
    [token],
  );
  const record = rows[0];
  if (!record) {
    res.status(400).json({ error: 'invalid_or_used_token' });
    return;
  }
  const hash = await bcrypt.hash(String(new_password || ''), 8);
  await pool.query(`UPDATE users SET password_hash = $1 WHERE email = $2`, [hash, record.email]);
  await pool.query(`UPDATE reset_tokens SET used = TRUE WHERE id = $1`, [record.id]);
  await pool.query(
    `INSERT INTO audit_log (actor, action, detail) VALUES ($1, 'password_changed', 'via reset')`,
    [record.email],
  );
  res.json({ status: 'password_updated', email: record.email });
});

export default router;
