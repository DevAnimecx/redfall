import { Router, Request, Response } from 'express';
import pool from '../db';
import { requireAuth, AuthedRequest } from '../middleware/jwt';

const router = Router();

interface TransferBody {
  to?: unknown;
  amount?: unknown;
  note?: unknown;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// VULN-013: the balance is read, then the write happens after an await. Two
// concurrent transfers both read the same balance and both pass the check, so the
// account can be driven negative (CWE-362). There is no transaction and no row lock.
// VULN-014: `amount` is only checked for being a number, so a negative value
// reverses the transfer direction and credits the sender (CWE-20).
router.post('/', requireAuth, async (req: AuthedRequest, res: Response) => {
  const body = (req.body || {}) as TransferBody;
  const to = Number(body.to);
  const amount = Number(body.amount);
  const note = typeof body.note === 'string' ? body.note : '';
  const me = req.user!.id;

  if (!Number.isInteger(to) || to <= 0) {
    res.status(400).json({ error: 'invalid_recipient' });
    return;
  }
  if (!Number.isFinite(amount) || amount === 0) {
    res.status(400).json({ error: 'invalid_amount' });
    return;
  }
  if (to === me) {
    res.status(400).json({ error: 'cannot_transfer_to_self' });
    return;
  }

  try {
    const meRow = await pool.query(`SELECT balance FROM users WHERE id = $1`, [me]);
    if (meRow.rowCount === 0) {
      res.status(404).json({ error: 'sender_not_found' });
      return;
    }
    const peerRow = await pool.query(`SELECT id FROM users WHERE id = $1`, [to]);
    if (peerRow.rowCount === 0) {
      res.status(404).json({ error: 'recipient_not_found' });
      return;
    }

    const balance = Number(meRow.rows[0].balance);
    // Check-then-act with a gap in between: the window the race exploits.
    await sleep(120);

    if (amount > 0 && balance < amount) {
      res.status(400).json({ error: 'insufficient_funds', balance });
      return;
    }

    await pool.query(`UPDATE users SET balance = balance - $1 WHERE id = $2`, [amount, me]);
    await pool.query(`UPDATE users SET balance = balance + $1 WHERE id = $2`, [amount, to]);
    const tx = await pool.query(
      `INSERT INTO transactions (owner_id, kind, counterparty, amount, note)
       VALUES ($1, 'transfer', $2, $3, $4) RETURNING id, owner_id, kind, counterparty, amount, note`,
      [me, String(to), amount, note],
    );

    const after = await pool.query(`SELECT balance FROM users WHERE id = $1`, [me]);
    res.status(201).json({ transaction: tx.rows[0], balance_after: Number(after.rows[0].balance) });
  } catch (err) {
    res.status(500).json({ error: 'transfer_failed', detail: (err as Error).message });
  }
});

// VULN-015: transaction lookup by id with no ownership check (CWE-639).
router.get('/:id', requireAuth, async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: 'invalid_id' });
    return;
  }
  try {
    const result = await pool.query(
      `SELECT t.id, t.owner_id, u.username AS owner, t.kind, t.counterparty, t.amount, t.note, t.created_at
       FROM transactions t JOIN users u ON u.id = t.owner_id
       WHERE t.id = $1`,
      [id],
    );
    if (result.rowCount === 0) {
      res.status(404).json({ error: 'transaction_not_found' });
      return;
    }
    res.status(200).json({ transaction: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'lookup_failed', detail: (err as Error).message });
  }
});

export default router;
