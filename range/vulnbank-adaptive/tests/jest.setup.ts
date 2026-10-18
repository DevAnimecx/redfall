// Jest process-wide environment. The exec endpoint (src/routes/admin.ts) shells
// out to psql, so DATABASE_URL has to be present in the test process too.
process.env.DB_HOST = process.env.DB_HOST || '127.0.0.1';
process.env.DB_PORT = process.env.DB_PORT || '5432';
process.env.DB_NAME = process.env.DB_NAME || 'vulnbank_v2';
process.env.DB_USER = process.env.DB_USER || 'vulnbank';
process.env.DB_PASSWORD = process.env.DB_PASSWORD || 'Sup3rS3cretBankPwd!';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-only-jwt-secret-value';
process.env.STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_test_only_value';
process.env.DATABASE_URL =
  process.env.DATABASE_URL ||
  `postgresql://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`;

export {};
