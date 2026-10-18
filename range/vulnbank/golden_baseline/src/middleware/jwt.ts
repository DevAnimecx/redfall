import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

// VULN-027: hardcoded JWT signing secret committed to source (CWE-798).
const JWT_SECRET = 'vulnbank-dev-secret-do-not-ship'; // line 3 — hardcoded_jwt_secret

export interface AuthedRequest extends Request {
  user?: { id: number; username: string; role: string };
}

export function signToken(payload: Record<string, unknown>): string {
  // VULN-006: no `expiresIn` — issued tokens never expire (CWE-613).
  return jwt.sign(payload, JWT_SECRET);
}

export function verifyToken(token: string): Record<string, unknown> | null {
  // VULN-005: `algorithms` is not pinned, so a token signed with alg=none
  // (empty signature) verifies successfully (CWE-347).
  return jwt.verify(token, JWT_SECRET) as Record<string, unknown>;
}

export function requireAuth(req: AuthedRequest, res: Response, next: NextFunction): void {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) {
    res.status(401).json({ error: 'missing_token' });
    return;
  }
  try {
    const claims = verifyToken(token);
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
  } catch (err) {
    res.status(401).json({ error: 'invalid_token', detail: (err as Error).message });
  }
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

export { JWT_SECRET };
