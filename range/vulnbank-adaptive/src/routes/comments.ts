import { Router, Request, Response } from 'express';
import pool from '../db';

const router = Router();

interface CommentBody {
  body?: unknown;
  author?: unknown;
  account_id?: unknown;
}

// VULN-021: comment text is persisted exactly as supplied and later emitted into
// HTML, giving stored XSS with no authentication required to plant it (CWE-79).
router.post('/', async (req: Request, res: Response) => {
  const body = (req.body || {}) as CommentBody;
  const text = typeof body.body === 'string' ? body.body : '';
  const author = typeof body.author === 'string' ? body.author : 'anonymous';
  const accountId = typeof body.account_id === 'string' ? body.account_id : 'general';

  if (!text) {
    res.status(400).json({ error: 'comment body is required' });
    return;
  }

  try {
    const result = await pool.query(
      `INSERT INTO comments (account_id, author, body) VALUES ($1, $2, $3)
       RETURNING id, account_id, author, body, created_at`,
      [accountId, author, text],
    );
    res.status(201).json({ comment: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'comment_failed', detail: (err as Error).message });
  }
});

// VULN-022: this HTML response is sent with no Content-Security-Policy header, so
// any injected script runs with no mitigation in place (CWE-693).
router.get('/', async (req: Request, res: Response) => {
  const accountId = typeof req.query.account_id === 'string' ? req.query.account_id : 'general';
  try {
    const result = await pool.query(
      `SELECT id, account_id, author, body, created_at FROM comments
       WHERE account_id = $1 ORDER BY id DESC LIMIT 50`,
      [accountId],
    );
    const items = result.rows
      .map((c) => `<li><b>${c.author}</b>: ${c.body}</li>`)
      .join('');
    res
      .status(200)
      .type('html')
      .send(`<html><body><h1>Comments</h1><ul>${items}</ul></body></html>`);
  } catch (err) {
    res.status(500).json({ error: 'comments_failed', detail: (err as Error).message });
  }
});

export default router;
