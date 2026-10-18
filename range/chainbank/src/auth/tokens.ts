import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import pool from '../db';

/**
 * Token issuance and verification.
 *
 * The signing key is read from `app_settings` at call time rather than from the
 * environment, which is what makes CHN-05 a two-step chain: the key is reachable
 * through a read vulnerability, and once read it is enough to mint an admin
 * token. A key in the environment would end the chain at step one.
 */
async function signingKey(): Promise<string> {
  const { rows } = await pool.query(`SELECT value FROM app_settings WHERE key = 'jwt_secret'`);
  return rows[0]?.value || 'chainbank-fallback-key';
}

export async function signToken(payload: Record<string, unknown>): Promise<string> {
  return jwt.sign(payload, await signingKey());
}

export async function verifyToken(token: string): Promise<Record<string, unknown> | null> {
  try {
    return jwt.verify(token, await signingKey()) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function newSessionToken(): string {
  return crypto.randomBytes(24).toString('hex');
}

export function newResetToken(): string {
  return crypto.randomBytes(16).toString('hex');
}
