import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../auth/tokens';
import pool from '../db';

export interface AuthedRequest extends Request {
  user?: { id: number; username: string; role: string };
}

export async function requireAuth(
  req: AuthedRequest,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) {
    res.status(401).json({ error: 'missing_token' });
    return;
  }
  const claims = await verifyToken(token);
  if (!claims || typeof claims.sub !== 'number') {
    res.status(401).json({ error: 'invalid_token' });
    return;
  }
  req.user = {
    id: Number(claims.sub),
    username: String(claims.username || ''),
    role: String(claims.role || 'customer'),
  };
  next();
}

export async function requireSessionToken(
  req: AuthedRequest,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.role FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.token = $1`,
    [token],
  );
  if (!rows[0]) {
    res.status(401).json({ error: 'unknown_session' });
    return;
  }
  req.user = { id: rows[0].id, username: rows[0].username, role: rows[0].role };
  next();
}

export function requireAdmin(req: AuthedRequest, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ error: 'missing_token' });
    return;
  }
  if (req.user.role !== 'admin') {
    res.status(403).json({ error: 'admin_only' });
    return;
  }
  next();
}
