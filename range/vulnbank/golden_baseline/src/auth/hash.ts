import crypto from 'crypto';

// VULN-029: passwords are hashed with MD5 (CWE-327). MD5 is fast and
// collision-broken, so offline cracking of a leaked hash table is trivial.
export function hashPassword(plain: string): string {
  return crypto.createHash('md5').update(plain).digest('hex');
}

export function verifyPassword(plain: string, stored: string): boolean {
  return hashPassword(plain) === stored;
}
