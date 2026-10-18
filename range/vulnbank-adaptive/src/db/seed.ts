import pool from '../db';
import { ensureSchema, truncateAll } from './schema';
import { hashPassword } from '../auth/hash';

export const SEED_USERS = [
  { username: 'admin', password: 'Adm1n!Passw0rd', email: 'admin@vulnbank.test', role: 'admin', balance: 500000.0, kyc: true },
  { username: 'alice', password: 'Alice!Passw0rd1', email: 'alice@vulnbank.test', role: 'customer', balance: 2500.0, kyc: true },
  { username: 'bob', password: 'Bob!Passw0rd22', email: 'bob@vulnbank.test', role: 'customer', balance: 1200.0, kyc: true },
  { username: 'carol', password: 'Carol!Passw0rd3', email: 'carol@vulnbank.test', role: 'customer', balance: 75.5, kyc: false },
];

export async function seed(): Promise<void> {
  await ensureSchema();
  await truncateAll();

  for (const u of SEED_USERS) {
    const res = await pool.query(
      `INSERT INTO users (username, password, email, role, balance, kyc_complete)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [u.username, hashPassword(u.password), u.email, u.role, u.balance, u.kyc],
    );
    const id = res.rows[0].id;
    await pool.query(
      `INSERT INTO profiles (user_id, display_name, bio, website) VALUES ($1, $2, $3, $4)`,
      [id, u.username.toUpperCase(), `Seed bio for ${u.username}`, 'https://vulnbank.test'],
    );
  }

  const ids: Record<string, number> = {};
  for (const u of SEED_USERS) {
    const r = await pool.query(`SELECT id FROM users WHERE username = $1`, [u.username]);
    ids[u.username] = r.rows[0].id;
  }

  const txRows: Array<[number, string, string, number, string]> = [
    [ids.alice, 'deposit', 'payroll', 1500.0, 'May salary'],
    [ids.alice, 'transfer', 'bob', -250.0, 'Rent split'],
    [ids.bob, 'deposit', 'payroll', 900.0, 'May salary'],
    [ids.carol, 'deposit', 'cash', 75.5, 'ATM deposit'],
  ];
  for (const [owner, kind, cp, amount, note] of txRows) {
    await pool.query(
      `INSERT INTO transactions (owner_id, kind, counterparty, amount, note) VALUES ($1,$2,$3,$4,$5)`,
      [owner, kind, cp, amount, note],
    );
  }

  await pool.query(
    `INSERT INTO comments (account_id, author, body) VALUES ($1, $2, $3)`,
    ['general', 'alice', 'Welcome to the community board.'],
  );
  await pool.query(
    `INSERT INTO settings (owner_id, payload) VALUES ($1, $2)`,
    [ids.alice, JSON.stringify({ theme: 'dark', notifications: true })],
  );
  await pool.query(
    `INSERT INTO audit_log (actor, action, detail) VALUES ($1, $2, $3)`,
    ['system', 'seed', 'range seed completed'],
  );

  // Redfall 0.1.0 configuration. These rows are the reason routes exist that no
  // source file names, and the reason a query can be changed without a deploy.
  await pool.query(
    `INSERT INTO route_config (name, method, path, handler_key, enabled) VALUES
       ('legacy_reports', 'GET', '/legacy/reports', 'legacyReports', true),
       ('legacy_ledger',  'GET', '/legacy/ledger',  'legacyLedger',  true)
     ON CONFLICT (name) DO UPDATE
       SET method = EXCLUDED.method,
           path = EXCLUDED.path,
           handler_key = EXCLUDED.handler_key,
           enabled = EXCLUDED.enabled`,
  );
  await pool.query(
    `INSERT INTO query_config (key, sql) VALUES
       ('legacyReports', 'SELECT id, kind, amount, note FROM transactions'),
       ('legacyLedger',  'SELECT id, username, role, balance FROM users')
     ON CONFLICT (key) DO UPDATE SET sql = EXCLUDED.sql, updated_at = now()`,
  );
}

if (require.main === module) {
  seed()
    .then(() => {
      console.log('seed: ok');
      return pool.end();
    })
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('seed failed:', err.message);
      process.exit(1);
    });
}
