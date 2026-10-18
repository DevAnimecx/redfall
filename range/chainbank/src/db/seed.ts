import bcrypt from 'bcryptjs';
import pool from '../db';
import { SCHEMA, TRUNCATE } from './schema';

export const SEED_PASSWORDS = {
  admin: 'Admin!Passw0rd',
  alice: 'Alice!Passw0rd',
  bob: 'Bob!Passw0rd',
  carol: 'Carol!Passw0rd',
};

/**
 * Seed chainbank.
 *
 * Idempotent: wipes the rows and re-inserts, so a test run and a manual run
 * leave the same database. Passwords are hashed for real — the point of the
 * target is that the hashes are only recoverable through a vulnerability, not
 * that they are weak.
 */
export async function seed(): Promise<void> {
  await pool.query(SCHEMA);
  for (const table of TRUNCATE) {
    await pool.query(`TRUNCATE TABLE ${table} RESTART IDENTITY CASCADE`);
  }

  const rows: Array<[string, string, string, string, number]> = [
    ['admin', 'admin@chainbank.test', SEED_PASSWORDS.admin, 'admin', 950000],
    ['alice', 'alice@chainbank.test', SEED_PASSWORDS.alice, 'customer', 42000],
    ['bob', 'bob@chainbank.test', SEED_PASSWORDS.bob, 'customer', 18500],
    ['carol', 'carol@chainbank.test', SEED_PASSWORDS.carol, 'customer', 7300],
  ];
  for (const [username, email, password, role, balance] of rows) {
    const hash = await bcrypt.hash(password, 8);
    await pool.query(
      'INSERT INTO users (username, email, password_hash, role, balance) VALUES ($1,$2,$3,$4,$5)',
      [username, email, hash, role, balance],
    );
  }

  const accounts: Array<[string, string, string, number]> = [
    ['CB-ADMIN-001', 'admin@chainbank.test', 'Treasury', 950000],
    ['CB-0001', 'alice@chainbank.test', 'Alice checking', 42000],
    ['CB-0002', 'bob@chainbank.test', 'Bob checking', 18500],
    ['CB-0003', 'carol@chainbank.test', 'Carol savings', 7300],
  ];
  for (const [accountNo, owner, label, balance] of accounts) {
    await pool.query(
      'INSERT INTO accounts (account_no, owner_email, label, balance) VALUES ($1,$2,$3,$4)',
      [accountNo, owner, label, balance],
    );
  }

  await pool.query(
    `INSERT INTO app_settings (key, value) VALUES
       ('jwt_secret', $1),
       ('cloud_access_key', $2),
       ('cloud_secret_key', $3),
       ('support_email', 'support@chainbank.test')`,
    ['chainbank-jwt-signing-key-do-not-share', 'AKIACHAINBANKEXAMPLE', 'wJalrXUtnFEMI/chainbank/secret/key'],
  );
}

if (require.main === module) {
  seed()
    .then(async () => {
      console.log('chainbank seeded');
      await pool.end();
    })
    .catch(async (err) => {
      console.error('seed failed', err);
      await pool.end();
      process.exit(1);
    });
}
