import { Router } from 'express';
import pool from '../db';

const router = Router();

/**
 * CHN-01, step A — account lookup with no ownership check.
 *
 * The route is intentionally unauthenticated: chainbank models a support tool
 * that lets staff look a customer up by account number. Because it returns the
 * owner's email address, it is the first half of an account takeover — the email
 * is what the password-reset endpoint in `auth.ts` needs.
 */
router.get('/:accountNo', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT account_no, owner_email, label, balance FROM accounts WHERE account_no = $1`,
    [req.params.accountNo],
  );
  if (!rows[0]) {
    res.status(404).json({ error: 'no_such_account' });
    return;
  }
  res.json({ account: rows[0] });
});

export default router;
