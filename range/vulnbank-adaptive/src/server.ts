import { createApp, registerDynamicRoutes } from './app';
import pool from './db';
import { seed } from './db/seed';

const PORT = Number(process.env.PORT || 4000);

async function main(): Promise<void> {
  if (process.env.SEED_ON_BOOT !== 'false') {
    await seed();
    console.log('[boot] database seeded');
  }
  const app = createApp();
  // The route set is data, so it can only be known once the database is up.
  const dynamic = await registerDynamicRoutes(app);
  for (const route of dynamic) {
    console.log(`[boot] dynamic route ${route.method} ${route.path} (from route_config:${route.name})`);
  }
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[boot] vulnbank-adaptive listening on :${PORT}`);
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
