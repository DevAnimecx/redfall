import { Router, Request, Response } from 'express';
import pool from '../db';

const router = Router();

interface StripeEvent {
  type?: unknown;
  data?: { object?: { id?: unknown; amount?: unknown; customer?: unknown } };
}

// VULN-025: the event is trusted purely from the JSON body. The
// `Stripe-Signature` header is never read and never HMAC-verified, so anyone can
// forge a charge.succeeded event and credit an account (CWE-347).
router.post('/stripe', async (req: Request, res: Response) => {
  const event = (req.body || {}) as StripeEvent;
  const type = typeof event.type === 'string' ? event.type : '';

  if (!type) {
    res.status(400).json({ error: 'event type is required' });
    return;
  }

  try {
    if (type === 'charge.succeeded') {
      const obj = event.data?.object || {};
      const username = String(obj.customer || '');
      const amount = Number(obj.amount || 0) / 100;
      const updated = await pool.query(
        `UPDATE users SET balance = balance + $1 WHERE username = $2 RETURNING id, username, balance`,
        [amount, username],
      );
      if (updated.rowCount === 0) {
        res.status(404).json({ error: 'customer_not_found' });
        return;
      }
      res.status(200).json({ received: true, credited: updated.rows[0] });
      return;
    }

    await pool.query(
      `INSERT INTO audit_log (actor, action, detail) VALUES ($1, $2, $3)`,
      ['stripe', type, JSON.stringify(event).slice(0, 500)],
    );
    res.status(200).json({ received: true });
  } catch (err) {
    res.status(500).json({ error: 'webhook_failed', detail: (err as Error).message });
  }
});

export default router;
