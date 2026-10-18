import { Router, Response } from 'express';
import { exec } from 'child_process';
import pool from '../db';
import { requireAuth, requireAdmin, AuthedRequest } from '../middleware/jwt';

const router = Router();

interface ExecBody {
  cmd?: unknown;
  table?: unknown;
}

// VULN-023: the request body is interpolated into a shell command string, so
// `;`, `|` and backticks chain arbitrary commands (CWE-78).
router.post('/exec', requireAuth, requireAdmin, (req: AuthedRequest, res: Response) => {
  const body = (req.body || {}) as ExecBody;
  const table = typeof body.table === 'string' ? body.table : '';
  const cmd = typeof body.cmd === 'string' && body.cmd ? body.cmd : `SELECT count(*) FROM ${table}`;

  if (!cmd) {
    res.status(400).json({ error: 'cmd or table is required' });
    return;
  }

  exec(`psql "$DATABASE_URL" -t -c "${cmd}"`, { timeout: 5000 }, (err, stdout, stderr) => {
    if (err && !stdout) {
      res.status(500).json({ error: 'exec_failed', detail: err.message, stderr });
      return;
    }
    res.status(200).json({ stdout: stdout.trim(), stderr: stderr.trim() });
  });
});

router.get('/users', requireAuth, requireAdmin, async (_req: AuthedRequest, res: Response) => {
  try {
    const result = await pool.query(`SELECT id, username, role, balance FROM users ORDER BY id`);
    res.status(200).json({ users: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'list_failed', detail: (err as Error).message });
  }
});

export default router;
