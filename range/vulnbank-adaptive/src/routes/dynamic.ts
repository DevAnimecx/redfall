import { Router, Request, Response } from 'express';

import pool from '../db';

/**
 * VULN-033 — dynamic route registration (CWE-94 adjacent: code path chosen by data).
 *
 * The routes served here are not written anywhere in this file. Their methods,
 * paths and handler keys come from the `route_config` table, so the HTTP surface
 * of the application is only knowable by reading that table or asking the
 * running process. A scanner that only parses source cannot see them.
 */

type HandlerKey = 'legacyReports' | 'legacyLedger';

interface RouteRow {
  name: string;
  method: string;
  path: string;
  handler_key: HandlerKey;
  enabled: boolean;
}

/**
 * Load whatever route_config says should exist, and register it.
 *
 * Returns the routes it registered so the caller can log or expose them.
 */
/** The subset of Express a router registration actually needs. */
type RouteRegistrar = {
  [K in 'get' | 'post' | 'put' | 'delete' | 'patch' | 'head' | 'options' | 'all']: (
    path: string,
    handler: (req: Request, res: Response) => unknown,
  ) => unknown;
};

export async function loadRouteFromDB(app: RouteRegistrar): Promise<RouteRow[]> {
  const { rows } = await pool.query(
    `SELECT name, method, path, handler_key, enabled FROM route_config WHERE enabled = true ORDER BY name`,
  );
  const registered: RouteRow[] = [];

  for (const row of rows as RouteRow[]) {
    const handler = HANDLERS[row.handler_key];
    if (!handler) {
      continue;
    }
    const verb = row.method.toLowerCase();
    const register = (app as unknown as Record<string, ((path: string, h: unknown) => void) | undefined>)[verb];
    if (typeof register !== 'function') {
      continue;
    }
    register.call(app, row.path, handler);
    registered.push(row);
  }
  return registered;
}

/**
 * VULN-037 — second-order SQL execution (CWE-89).
 *
 * The SQL text does not live in this file either. It is read out of
 * `query_config` and executed. The request's `filter` value is interpolated
 * straight into that text before it runs, so a caller who can influence either
 * the row or the parameter controls the statement.
 */
async function runStoredQuery(key: string, filter: string | undefined): Promise<unknown[]> {
  const { rows } = await pool.query(`SELECT sql FROM query_config WHERE key = $1`, [key]);
  if (rows.length === 0) {
    return [];
  }
  const base = String(rows[0].sql);
  // The interpolation is the vulnerability: no quoting, no parameter binding.
  // The clause order is built here so that a stored query without a WHERE still
  // produces valid SQL, which is what makes the injection reachable at all.
  const sql =
    filter === undefined ? `${base} ORDER BY 1` : `${base} WHERE ${filter} ORDER BY 1`;
  const result = await pool.query(sql);
  return result.rows;
}

const HANDLERS: Record<HandlerKey, (req: Request, res: Response) => Promise<void>> = {
  legacyReports: async (req: Request, res: Response) => {
    const rows = await runStoredQuery('legacyReports', typeof req.query.filter === 'string' ? req.query.filter : undefined);
    res.status(200).json({ rows });
  },
  legacyLedger: async (req: Request, res: Response) => {
    const rows = await runStoredQuery('legacyLedger', typeof req.query.filter === 'string' ? req.query.filter : undefined);
    res.status(200).json({ rows });
  },
};

/**
 * VULN-033's discovery surface.
 *
 * This is how the dynamic routes become knowable at runtime: the application
 * happily lists the paths it registered from the database, including the SQL
 * each one runs. Anything that can read this response can then attack a route
 * that static analysis never saw.
 */
export function routeInventoryRouter(): Router {
  const router = Router();

  router.get('/', async (_req: Request, res: Response) => {
    const { rows } = await pool.query(
      `SELECT name, method, path, handler_key, enabled FROM route_config ORDER BY name`,
    );
    const queries = await pool.query(`SELECT key, sql FROM query_config ORDER BY key`);
    res.status(200).json({
      routes: rows,
      stored_queries: queries.rows,
      note: 'routes are registered from route_config at boot; see loadRouteFromDB',
    });
  });

  return router;
}

export default loadRouteFromDB;
