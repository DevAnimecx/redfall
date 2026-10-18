import { Router } from 'express';
import pool from '../db';

const router = Router();

/**
 * CHN-04, step B — the cloud metadata service.
 *
 * Models the instance metadata endpoint every cloud provider exposes on a
 * link-local address. It authenticates nothing, because it assumes the network
 * boundary is the authentication. Reachable by SSRF, it hands over long-lived
 * cloud credentials.
 */
router.get('/metadata/iam/credentials', async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT key, value FROM app_settings WHERE key IN ('cloud_access_key','cloud_secret_key')`,
  );
  const creds = Object.fromEntries(rows.map((r) => [r.key, r.value]));
  res.json({
    Code: 'Success',
    Type: 'AWS-HMAC',
    AccessKeyId: creds.cloud_access_key,
    SecretAccessKey: creds.cloud_secret_key,
    Token: 'chainbank-instance-session-token',
    Expiration: new Date(Date.now() + 6 * 3600 * 1000).toISOString(),
  });
});

/**
 * Proves the stolen credentials work, so the chain has a demonstrable end state
 * rather than a value that merely looks like a key.
 */
router.post('/cloud/assume', async (req, res) => {
  const { access_key, secret_key } = req.body || {};
  const { rows } = await pool.query(
    `SELECT key, value FROM app_settings WHERE key IN ('cloud_access_key','cloud_secret_key')`,
  );
  const expected = Object.fromEntries(rows.map((r) => [r.key, r.value]));
  if (access_key !== expected.cloud_access_key || secret_key !== expected.cloud_secret_key) {
    res.status(403).json({ error: 'invalid_cloud_credentials' });
    return;
  }
  await pool.query(
    `INSERT INTO audit_log (actor, action, detail) VALUES ('cloud', 'role_assumed', $1)`,
    [String(access_key)],
  );
  res.json({ assumed: true, role: 'arn:aws:iam::chainbank:role/treasury-export' });
});

export default router;
