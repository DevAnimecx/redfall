import { Router } from 'express';
import pool from '../db';
import { requireSessionToken, AuthedRequest } from '../middleware/auth';

const router = Router();

/** CHN-06 proof: a stolen token authenticates here as its owner. */
router.get('/', requireSessionToken, async (req: AuthedRequest, res) => {
  const { rows } = await pool.query(
    `SELECT id, username, email, role, balance FROM users WHERE id = $1`,
    [req.user!.id],
  );
  res.json({ user: rows[0] });
});

export default router;
