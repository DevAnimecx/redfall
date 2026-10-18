import { Pool } from 'pg';

// VULN-028: hardcoded database credentials (CWE-798).
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || 'vulnbank',
  user: process.env.DB_USER || 'vulnbank',
  password: 'Sup3rS3cretBankPwd!', // line 7 — hardcoded_db_password
  max: 10,
});

pool.on('error', (err) => {
  // Keep the process alive on idle-client errors; log only.
  console.error('[db] idle client error', err.message);
});

export default pool;
