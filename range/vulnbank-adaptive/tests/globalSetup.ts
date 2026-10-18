import { seed } from '../src/db/seed';
import pool from '../src/db';

// globalSetup runs in the real Jest parent process, not in a sandboxed worker,
// so environment variables assigned here reach child processes spawned later
// (src/routes/admin.ts shells out to psql and needs DATABASE_URL).
module.exports = async (): Promise<void> => {
  const host = process.env.DB_HOST || '127.0.0.1';
  const port = process.env.DB_PORT || '5432';
  const name = process.env.DB_NAME || 'vulnbank_v2';
  const user = process.env.DB_USER || 'vulnbank';

  process.env.DB_HOST = host;
  process.env.DB_PORT = port;
  process.env.DB_NAME = name;
  process.env.DB_USER = user;
  process.env.DB_PASSWORD = process.env.DB_PASSWORD || 'Sup3rS3cretBankPwd!';
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-only-jwt-secret-value';
  process.env.STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_test_only_value';
  process.env.DATABASE_URL =
    process.env.DATABASE_URL || `postgresql://${user}:${process.env.DB_PASSWORD}@${host}:${port}/${name}`;

  await seed();
  await pool.end();
};
