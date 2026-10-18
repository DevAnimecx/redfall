import { Pool } from 'pg';

const pool = new Pool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || 'chainbank',
  user: process.env.DB_USER || 'chainbank',
  password: process.env.DB_PASSWORD || 'Chainbank!Pwd',
  max: 10,
});

pool.on('error', (err) => {
  console.error('[db] idle client error', err.message);
});

export default pool;
