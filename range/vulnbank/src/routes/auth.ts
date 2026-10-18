import { Router, Request, Response } from 'express';
import pool from '../db';
import { signToken, verifyToken } from '../middleware/jwt';
import { hashPassword, verifyPassword } from '../auth/hash';

const router = Router();

interface LoginBody {
  username?: unknown;
  password?: unknown;
}

interface RegisterBody {
  username?: unknown;
  password?: unknown;
  email?: unknown;
  [key: string]: unknown;
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

export function loginHandler(req: Request, res: Response): void {
  const body = (req.body || {}) as LoginBody;
  const username = asString(body.username);
  const password = asString(body.password);

  if (!username || !password) {
    res.status(400).json({ error: 'username and password are required' });
    return;
  }

  // VULN-001: the username is concatenated straight into the SQL string, so a
  // classic UNION SELECT payload rewrites the result set (CWE-89).
  // VULN-002: there is no rate limiter on this handler, so credential stuffing
  // and brute force run unthrottled (CWE-307).
  const lookup = `SELECT id, username, password, email, role, balance
                  FROM users
                  WHERE username = '${username}'`;
  pool
    .query(lookup)
    .then((result) => {
      const row = result.rows[0];
      if (!row) {
        // VULN-003: the "unknown user" path returns a distinct message from the
        // "wrong password" path, which lets anyone enumerate accounts (CWE-204).
        // VULN-004: the unknown-user path also skips password verification
        // entirely, so its response time differs from a real-user lookup (CWE-208).
        res.status(401).json({ error: 'no such user', field: 'username' });
        return;
      }
      if (!verifyPassword(password, row.password)) {
        res.status(401).json({ error: 'wrong password', field: 'password' });
        return;
      }
      const token = signToken({ sub: row.id, username: row.username, role: row.role });
      res.status(200).json({
        token,
        user: { id: row.id, username: row.username, email: row.email, role: row.role },
      });
    })
    .catch((err) => {
      res.status(500).json({ error: 'login_failed', detail: (err as Error).message });
    });
}

router.post('/login', loginHandler);

router.post('/register', (req: Request, res: Response) => {
  const body = (req.body || {}) as RegisterBody;
  const username = asString(body.username);
  const password = asString(body.password);
  const email = asString(body.email);

  if (!username || !password || !email) {
    res.status(400).json({ error: 'username, password and email are required' });
    return;
  }

  // VULN-007: the request body is spread directly into the INSERT column list,
  // so a caller can add role, balance or kyc_complete to self-escalate (CWE-915).
  const fields: Record<string, unknown> = { ...body };
  delete fields.password;
  // Hashed with the same MD5 helper login verifies against (VULN-029).
  const columns = ['username', 'email', ...Object.keys(fields).filter((k) => k !== 'username' && k !== 'email')];
  const placeholders = columns.map((_c, i) => `$${i + 1}`);
  const values = columns.map((c) => (c === 'username' ? username : c === 'email' ? email : fields[c]));

  pool
    .query(
      `INSERT INTO users (${columns.join(', ')}, password)
       VALUES (${placeholders.join(', ')}, $${columns.length + 1})
       RETURNING id, username, email, role, balance, kyc_complete`,
      [...values, hashPassword(password)],
    )
    .then((result) => {
      const row = result.rows[0];
      pool
        .query(`INSERT INTO profiles (user_id, display_name, bio) VALUES ($1, $2, '')`, [row.id, row.username])
        .catch(() => undefined);
      const token = signToken({ sub: row.id, username: row.username, role: row.role });
      res.status(201).json({ token, user: row });
    })
    .catch((err) => {
      const msg = (err as Error).message;
      if (msg.includes('duplicate key')) {
        res.status(409).json({ error: 'username or email already taken' });
        return;
      }
      res.status(500).json({ error: 'registration_failed', detail: msg });
    });
});

router.get('/verify', (req: Request, res: Response) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) {
    res.status(401).json({ error: 'missing_token' });
    return;
  }
  // VULN-005 (unpinned algorithms) and VULN-006 (no expiry) both surface here:
  // verifyToken does not pin the algorithm and the token carries no exp claim.
  try {
    const claims = verifyToken(token);
    res.status(200).json({ valid: true, claims });
  } catch (err) {
    res.status(401).json({ valid: false, error: (err as Error).message });
  }
});

router.get('/me', (req: Request, res: Response) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  try {
    const claims = verifyToken(token);
    res.status(200).json({ sub: claims.sub, username: claims.username, role: claims.role });
  } catch {
    res.status(401).json({ error: 'invalid_token' });
  }
});

export default router;
