import { createApp } from './app';
import pool from './db';
import { seed } from './db/seed';

const PORT = Number(process.env.PORT || 4000);

async function main(): Promise<void> {
  if (process.env.SEED_ON_BOOT !== 'false') {
    await seed();
    console.log('[boot] database seeded');
  }
  const app = createApp();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[boot] vulnbank listening on :${PORT}`);
  });
}

main().catch(async (err) => {
  console.error('[boot] fatal:', err);
  try {
    await pool.end();
  } catch {
    process.exit(1);
  }
  process.exit(1);
});
