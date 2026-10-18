import { createApp } from './app';
import pool from './db';

const port = Number(process.env.PORT || 4002);

async function main(): Promise<void> {
  await pool.query('SELECT 1');
  const server = createApp().listen(port, '0.0.0.0', () => {
    console.log(`chainbank listening on :${port}`);
  });
  const shutdown = async (signal: string): Promise<void> => {
    console.log(`chainbank received ${signal}, shutting down`);
    server.close();
    await pool.end();
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

main().catch((err) => {
  console.error('chainbank failed to start', err);
  process.exit(1);
});
