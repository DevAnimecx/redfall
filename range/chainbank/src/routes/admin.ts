import { Router } from 'express';
import pool from '../db';
import { requireAuth, requireAdmin, AuthedRequest } from '../middleware/auth';

const router = Router();

router.get('/users', requireAuth, requireAdmin, async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, username, email, role, balance FROM users ORDER BY id`,
  );
  res.json({ users: rows });
});

/**
 * CHN-05, step B — the admin action a forged token unlocks.
 */
router.post('/transfer', requireAuth, requireAdmin, async (req: AuthedRequest, res) => {
  const { from_account, to_account, amount, memo } = req.body || {};
  const value = Number(amount);
  if (!Number.isFinite(value) || value <= 0) {
    res.status(400).json({ error: 'invalid_amount' });
    return;
  }
  const { rows } = await pool.query(
    `SELECT balance FROM accounts WHERE account_no = $1`,
    [from_account],
  );
  if (!rows[0] || Number(rows[0].balance) < value) {
    res.status(400).json({ error: 'insufficient_funds' });
    return;
  }
  await pool.query(
    `UPDATE accounts SET balance = balance - $1 WHERE account_no = $2`,
    [value, from_account],
  );
  await pool.query(
    `UPDATE accounts SET balance = balance + $1 WHERE account_no = $2`,
    [value, to_account],
  );
  await pool.query(
    `INSERT INTO transfers (from_account, to_account, amount, memo, initiated_by)
     VALUES ($1, $2, $3, $4, $5)`,
    [from_account, to_account, value, memo || null, req.user?.username || 'anonymous'],
  );
  const after = await pool.query(
    `SELECT account_no, balance FROM accounts WHERE account_no = ANY($1) ORDER BY account_no`,
    [[from_account, to_account]],
  );
  res.json({ status: 'transferred', amount: value, accounts: after.rows });
});

router.get('/transfers', requireAuth, requireAdmin, async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, from_account, to_account, amount, memo, initiated_by, created_at
       FROM transfers ORDER BY id DESC LIMIT 50`,
  );
  res.json({ transfers: rows });
});

export default router;
