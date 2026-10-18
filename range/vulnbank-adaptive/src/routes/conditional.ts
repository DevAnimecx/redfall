import { Express, Request, Response } from 'express';

import pool from '../db';

/**
 * Three routes that only exist under a condition, so each is invisible to a
 * scanner that reads the source once and never runs the application under the
 * other condition.
 *
 * VULN-035 — feature_flag:   FEATURE_BETA_EXPORT=on enables an unreviewed route.
 * VULN-036 — webhook_discovery: WEBHOOK_ENABLED=true enables a webhook surface.
 * VULN-038 — env_conditional:  NODE_ENV=production enables /api/debug.
 */

/** VULN-035: the beta exporter. Gated behind a flag, never reviewed, injectable. */
function registerBetaExport(app: Express): void {
  app.get('/api/beta/export', async (req: Request, res: Response) => {
    const account = typeof req.query.account === 'string' ? req.query.account : 'general';
    // This route shipped behind a flag and never went through review, so it
    // still builds SQL by concatenation.
    const sql = `SELECT id, account_id, author, body FROM comments WHERE account_id = '${account}' ORDER BY id`;
    try {
      const { rows } = await pool.query(sql);
      res.status(200).json({ account, count: rows.length, rows });
    } catch (err) {
      res.status(500).json({ error: 'export_failed', detail: (err as Error).message, sql });
    }
  });
}

/** VULN-036: webhook registration plus the endpoint it feeds. */
function registerWebhooks(app: Express): void {
  app.post('/api/hooks/register', async (req: Request, res: Response) => {
    const url = typeof req.body?.url === 'string' ? req.body.url : '';
    const event = typeof req.body?.event === 'string' ? req.body.event : '*';
    if (!url) {
      res.status(400).json({ error: 'url_required' });
      return;
    }
    const { rows } = await pool.query(
      `INSERT INTO webhook_subscriptions (url, event) VALUES ($1, $2) RETURNING id, url, event`,
      [url, event],
    );
    res.status(201).json({ subscription: rows[0] });
  });

  app.get('/api/hooks', async (_req: Request, res: Response) => {
    const { rows } = await pool.query(`SELECT id, url, event FROM webhook_subscriptions ORDER BY id`);
    res.status(200).json({ subscriptions: rows });
  });

  // The delivery endpoint is itself unauthenticated and unverified, so anything
  // that discovers the surface can push events into the application.
  app.post('/api/hooks/deliver', async (req: Request, res: Response) => {
    const event = typeof req.body?.event === 'string' ? req.body.event : 'unknown';
    const actor = typeof req.body?.actor === 'string' ? req.body.actor : 'anonymous';
    await pool.query(`INSERT INTO audit_log (actor, action, detail) VALUES ($1, $2, $3)`, [
      actor,
      `webhook:${event}`,
      JSON.stringify(req.body || {}),
    ]);
    res.status(202).json({ accepted: true, event });
  });
}

/** VULN-038: production-only diagnostics that leak the process environment. */
function registerDebug(app: Express): void {
  app.get('/api/debug', (_req: Request, res: Response) => {
    // Registered only in production, which is exactly where it does the most
    // damage: it returns the live environment, including the signing secret.
    res.status(200).json({
      node_env: process.env.NODE_ENV,
      env: process.env,
      versions: process.versions,
      uptime_s: Math.round(process.uptime()),
    });
  });
}

export interface ConditionalSurface {
  name: string;
  route: string;
  condition: string;
}

/**
 * Register whichever conditional surfaces the current environment selects, and
 * report what was registered so the selection is observable.
 */
export function registerConditionalRoutes(app: Express): ConditionalSurface[] {
  const enabled: ConditionalSurface[] = [];

  if (process.env.FEATURE_BETA_EXPORT === 'on') {
    registerBetaExport(app);
    enabled.push({
      name: 'beta_export',
      route: 'GET /api/beta/export',
      condition: 'FEATURE_BETA_EXPORT=on',
    });
  }

  if (process.env.WEBHOOK_ENABLED === 'true') {
    registerWebhooks(app);
    enabled.push({
      name: 'webhooks',
      route: 'POST /api/hooks/register',
      condition: 'WEBHOOK_ENABLED=true',
    });
  }

  if (process.env.NODE_ENV === 'production') {
    registerDebug(app);
    enabled.push({
      name: 'debug',
      route: 'GET /api/debug',
      condition: 'NODE_ENV=production',
    });
  }

  return enabled;
}

export default registerConditionalRoutes;
