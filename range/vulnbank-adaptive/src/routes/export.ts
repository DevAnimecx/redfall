import { Router, Response } from 'express';
import pool from '../db';
import { requireAuth, AuthedRequest } from '../middleware/jwt';

const router = Router();

// VULN-024: cell values are written to CSV with no leading-character escaping, so
// a value beginning with `=`, `+`, `-` or `@` becomes a formula when the file is
// opened in a spreadsheet (CWE-1236).
router.get('/', requireAuth, async (_req: AuthedRequest, res: Response) => {
  try {
    const result = await pool.query(
      `SELECT t.id, t.owner_id, u.username, t.kind, t.counterparty, t.amount, t.note
       FROM transactions t JOIN users u ON u.id = t.owner_id ORDER BY t.id`,
    );

    const lines = ['id,owner,username,kind,counterparty,amount,note'];
    for (const r of result.rows) {
      lines.push([r.id, r.owner_id, r.username, r.kind, r.counterparty, r.amount, r.note].join(','));
    }

    res
      .status(200)
      .type('text/csv')
      .set('Content-Disposition', 'attachment; filename="transactions.csv"')
      .send(lines.join('\n') + '\n');
  } catch (err) {
    res.status(500).json({ error: 'export_failed', detail: (err as Error).message });
  }
});

export default router;
