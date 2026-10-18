import { seed } from '../src/db/seed';
import pool from '../src/db';

module.exports = async (): Promise<void> => {
  const host = process.env.DB_HOST || '127.0.0.1';
  const port = process.env.DB_PORT || '5432';
  const name = process.env.DB_NAME || 'chainbank';
  const user = process.env.DB_USER || 'chainbank';

  process.env.DB_HOST = host;
  process.env.DB_PORT = port;
  process.env.DB_NAME = name;
  process.env.DB_USER = user;
  process.env.DB_PASSWORD = process.env.DB_PASSWORD || 'Chainbank!Pwd';

  await seed();
  await pool.end();
};
