/**
 * Chainbank schema.
 *
 * Deliberately vulnerable range target. Never deploy.
 *
 * Chainbank exists to test exploit chaining, so its design constraint is
 * different from vulnbank's: every vulnerability here must be a usable step in a
 * longer path. A flaw that cannot be followed by another flaw is not interesting
 * to this target, so the schema is built around credentials, sessions, secrets
 * and files that one flaw hands to the next.
 */
export const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'customer',
  balance       NUMERIC(14,2) NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token      TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS accounts (
  id           SERIAL PRIMARY KEY,
  account_no   TEXT UNIQUE NOT NULL,
  owner_email  TEXT NOT NULL,
  label        TEXT NOT NULL,
  balance      NUMERIC(14,2) NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reset_tokens (
  id         SERIAL PRIMARY KEY,
  email      TEXT NOT NULL,
  token      TEXT NOT NULL,
  used       BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS documents (
  id          SERIAL PRIMARY KEY,
  filename    TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  uploaded_by TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS transfers (
  id           SERIAL PRIMARY KEY,
  from_account TEXT NOT NULL,
  to_account   TEXT NOT NULL,
  amount       NUMERIC(14,2) NOT NULL,
  memo         TEXT,
  initiated_by TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         SERIAL PRIMARY KEY,
  actor      TEXT NOT NULL,
  action     TEXT NOT NULL,
  detail     TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app_settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL
);
`;

export const TRUNCATE = [
  'audit_log',
  'transfers',
  'documents',
  'reset_tokens',
  'accounts',
  'sessions',
  'users',
  'app_settings',
];
