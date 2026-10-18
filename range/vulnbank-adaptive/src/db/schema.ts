import pool from '../db';

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id           SERIAL PRIMARY KEY,
  username     TEXT UNIQUE NOT NULL,
  password     TEXT NOT NULL,
  email        TEXT UNIQUE NOT NULL,
  role         TEXT NOT NULL DEFAULT 'customer',
  balance      NUMERIC(14,2) NOT NULL DEFAULT 0,
  kyc_complete BOOLEAN NOT NULL DEFAULT false,
  is_locked    BOOLEAN NOT NULL DEFAULT false,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS profiles (
  user_id      INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  display_name TEXT NOT NULL DEFAULT '',
  bio          TEXT NOT NULL DEFAULT '',
  website      TEXT NOT NULL DEFAULT '',
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS transactions (
  id          SERIAL PRIMARY KEY,
  owner_id    INTEGER NOT NULL REFERENCES users(id),
  kind        TEXT NOT NULL,
  counterparty TEXT NOT NULL DEFAULT '',
  amount      NUMERIC(14,2) NOT NULL,
  note        TEXT NOT NULL DEFAULT '',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS comments (
  id         SERIAL PRIMARY KEY,
  account_id TEXT NOT NULL DEFAULT 'general',
  author     TEXT NOT NULL DEFAULT 'anonymous',
  body       TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS files (
  id          SERIAL PRIMARY KEY,
  owner_id    INTEGER NOT NULL REFERENCES users(id),
  stored_name TEXT NOT NULL,
  original    TEXT NOT NULL,
  mime        TEXT NOT NULL DEFAULT 'application/octet-stream',
  size        INTEGER NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS settings (
  id         SERIAL PRIMARY KEY,
  owner_id   INTEGER NOT NULL REFERENCES users(id),
  payload    JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         SERIAL PRIMARY KEY,
  actor      TEXT NOT NULL,
  action     TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Redfall 0.1.0: routes that exist only because a row says so. The application never
-- names these paths in source, so static analysis alone cannot see them.
CREATE TABLE IF NOT EXISTS route_config (
  name        TEXT PRIMARY KEY,
  method      TEXT NOT NULL,
  path        TEXT NOT NULL,
  handler_key TEXT NOT NULL,
  enabled     BOOLEAN NOT NULL DEFAULT true
);

-- Redfall 0.1.0: SQL text that lives in the database and is executed later. A
-- second-order sink: whoever can write this table controls what runs.
CREATE TABLE IF NOT EXISTS query_config (
  key        TEXT PRIMARY KEY,
  sql        TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Redfall 0.1.0: webhook subscriptions registered at runtime.
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
  id         SERIAL PRIMARY KEY,
  url        TEXT NOT NULL,
  event      TEXT NOT NULL DEFAULT '*',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`;

export async function ensureSchema(): Promise<void> {
  await pool.query(SCHEMA_SQL);
  // The settings upsert keys on owner_id, so it needs a unique index. Idempotent,
  // so it also upgrades a database created by an earlier schema revision.
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS settings_owner_id_key ON settings (owner_id)`);
}

export async function truncateAll(): Promise<void> {
  // route_config and query_config are application configuration, not test data.
  // They survive a reset because routes are registered from route_config when
  // the app is constructed, and a wiped table would unregister them.
  await pool.query(`
    TRUNCATE TABLE audit_log, webhook_subscriptions, settings, files, comments,
                   transactions, profiles, users
    RESTART IDENTITY CASCADE
  `);
}
