import express, { Express, Router, Request, Response, NextFunction } from 'express';

import authRoutes from './routes/auth';
import userRoutes from './routes/users';
import profileRoutes from './routes/profile';
import txRoutes from './routes/tx';
import uploadRoutes from './routes/upload';
import fetchRoutes from './routes/fetch';
import redirectRoutes from './routes/redirect';
import commentRoutes from './routes/comments';
import adminRoutes from './routes/admin';
import exportRoutes from './routes/export';
import webhookRoutes from './routes/webhook';
import configRoutes from './routes/config';
import settingsRoutes from './routes/settings';
import importRoutes from './routes/import';
import { loadRouteFromDB, routeInventoryRouter } from './routes/dynamic';
import { pluginRouter } from './routes/plugins';
import { registerConditionalRoutes, type ConditionalSurface } from './routes/conditional';

export function createApp(): Express {
  const app = express();

  // VULN-032: the origin is wildcarded while credentials are allowed, so any
  // site can issue credentialed cross-origin reads (CWE-942). helmet is not
  // installed, which is also why no CSP is sent on any response (VULN-022).
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,Stripe-Signature');
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ extended: true, limit: '2mb' }));

  app.get('/health', (_req: Request, res: Response) => {
    res.status(200).json({ status: 'ok', service: 'vulnbank', version: '1.0.0' });
  });

  // A feature-flag endpoint that reads settings off a freshly created object.
  // Because it never assigns these keys itself, any value it returns came from
  // Object.prototype — which makes prototype pollution observable over HTTP.
  app.get('/api/flags', (_req: Request, res: Response) => {
    const flags: Record<string, unknown> = {};
    res.status(200).json({
      flags,
      isAdmin: (flags as { isAdmin?: unknown }).isAdmin ?? false,
      theme: (flags as { theme?: unknown }).theme ?? 'system',
      locale: (flags as { locale?: unknown }).locale ?? 'en-US',
    });
  });

  app.use('/api/auth', authRoutes);
  app.use('/api/users', userRoutes);
  app.use('/api/users', profileRoutes);
  app.use('/api/transactions', txRoutes);
  app.use('/api/upload', uploadRoutes);
  app.use('/api/fetch', fetchRoutes);
  app.use('/api/redirect', redirectRoutes);
  app.use('/api/comments', commentRoutes);
  app.use('/api/admin', adminRoutes);
  app.use('/api/export', exportRoutes);
  app.use('/api/webhook', webhookRoutes);
  app.use('/api/config', configRoutes);
  app.use('/api/settings', settingsRoutes);
  app.use('/api/import', importRoutes);

  // --- Redfall 0.1.1: surfaces that are not fixed at compile time -----------------
  //
  // Each of these exists for a different reason, and none of them is a route a
  // source-only scan can enumerate. They are registered before the 404 handler
  // so that late registration still takes effect.

  // VULN-033: the inventory of database-registered routes is readable.
  app.use('/api/routes', routeInventoryRouter());

  // VULN-034 / VULN-039: plugin loading, from an env var and from a directory.
  const pluginDir = process.env.PLUGIN_DIR || `${__dirname}/plugins`;
  app.use(pluginRouter(pluginDir));

  // VULN-035 / VULN-036 / VULN-038: environment- and flag-gated routes.
  conditionalSurfaces = registerConditionalRoutes(app);

  // Routes whose existence is decided by the database are registered onto this
  // router, which is already mounted. Mounting the router now — before the 404
  // handler — is what makes late registration actually take effect: Express
  // matches in registration order, so anything added to `app` after the 404
  // handler would never be reached.
  app.use(dynamicRouter);

  // Reports what the process actually registered, which is the only honest
  // answer for surfaces chosen by data or environment.
  app.get('/api/surfaces', (_req: Request, res: Response) => {
    res.status(200).json({
      dynamic_routes: dynamicRoutes,
      dynamic_routes_loaded: dynamicRoutes.length > 0,
      conditional: conditionalSurfaces,
      plugin_dir: pluginDir,
      plugin_path_env: process.env.PLUGIN_PATH || null,
      env: {
        NODE_ENV: process.env.NODE_ENV || null,
        FEATURE_BETA_EXPORT: process.env.FEATURE_BETA_EXPORT || null,
        WEBHOOK_ENABLED: process.env.WEBHOOK_ENABLED || null,
      },
    });
  });

  app.use((req: Request, res: Response) => {
    res.status(404).json({ error: 'not_found', path: req.path });
  });

  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    res.status(500).json({ error: 'internal_error', detail: err.message });
  });

  return app;
}

interface RouteRow {
  name: string;
  method: string;
  path: string;
  handler_key: string;
  enabled: boolean;
}

let dynamicRoutes: RouteRow[] = [];
let conditionalSurfaces: ConditionalSurface[] = [];

/** Mount point for routes that only exist because a row says so. */
export const dynamicRouter: Router = Router();

/**
 * Register the routes that `route_config` says should exist.
 *
 * This is async because the route set lives in the database, so it cannot be
 * known while the application is being constructed. `server.ts` calls it before
 * listening; anything inspecting the surface should call it first and then read
 * GET /api/surfaces.
 */
export async function registerDynamicRoutes(app?: Express): Promise<RouteRow[]> {
  // `app` is accepted for symmetry with the rest of the registration code, but
  // the routes go on the pre-mounted router so ordering cannot break them.
  void app;
  dynamicRoutes = (await loadRouteFromDB(dynamicRouter)) as RouteRow[];
  return dynamicRoutes;
}

/** The conditional surfaces selected by the current environment. */
export function getConditionalSurfaces(): ConditionalSurface[] {
  return conditionalSurfaces;
}

export default createApp;
