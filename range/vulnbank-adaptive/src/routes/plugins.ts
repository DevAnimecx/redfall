import { Router, Request, Response } from 'express';
import fs from 'fs';
import path from 'path';

/**
 * Two separate dynamic-code surfaces live here, because they have different
 * triggers and need to be discovered differently.
 *
 * VULN-034 — dynamic_import (CWE-94): the plugin to load is named by an
 * environment variable, so which code runs is decided outside the source tree.
 *
 * VULN-039 — plugin_system (CWE-94): every file in a directory is required on
 * boot. Adding a file to that directory adds an endpoint.
 */

export interface PluginRoute {
  path: string;
  handle: (req: Request, res: Response) => void;
}

export interface LoadedPlugin {
  source: 'env' | 'directory';
  file: string;
  routes: PluginRoute[];
}

/** VULN-034: `require(process.env.PLUGIN_PATH)`. */
export function loadPluginFromEnv(): LoadedPlugin | null {
  const target = process.env.PLUGIN_PATH;
  if (!target) {
    return null;
  }
  // The module is resolved from an environment value with no allowlist, so the
  // code that runs is chosen by whoever controls the environment.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const mod = require(target) as { routes?: PluginRoute[] };
  return { source: 'env', file: target, routes: mod.routes || [] };
}

/** VULN-039: directory-scan loader. */
export function loadPluginsFromDirectory(dir: string): LoadedPlugin[] {
  if (!fs.existsSync(dir)) {
    return [];
  }
  const loaded: LoadedPlugin[] = [];
  const seen = new Set<string>();
  for (const entry of fs.readdirSync(dir)) {
    const stem = entry.replace(/\.(js|ts)$/, '');
    if (entry !== stem && !entry.endsWith('.js') && !entry.endsWith('.ts')) {
      continue;
    }
    if (seen.has(stem)) {
      continue;
    }
    // A built tree has audit.js next to audit.ts; load one of them, not both.
    const candidates = [path.join(dir, `${stem}.js`), path.join(dir, `${stem}.ts`)];
    const full = candidates.find((candidate) => fs.existsSync(candidate));
    if (!full) {
      continue;
    }
    seen.add(stem);
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const mod = require(full) as { routes?: PluginRoute[] };
      loaded.push({ source: 'directory', file: path.basename(full), routes: mod.routes || [] });
    } catch {
      // A plugin that fails to load must not take the application down.
      continue;
    }
  }
  return loaded;
}

/**
 * Register every route from both loaders onto a router, and expose an inventory
 * so the loaded set is observable at runtime.
 */
export function pluginRouter(pluginDir: string): Router {
  const router = Router();
  const inventory: Array<{ source: string; file: string; path: string }> = [];

  const register = (plugin: LoadedPlugin): void => {
    for (const route of plugin.routes) {
      router.all(route.path, route.handle);
      inventory.push({ source: plugin.source, file: plugin.file, path: route.path });
    }
  };

  const fromEnv = loadPluginFromEnv();
  if (fromEnv) {
    register(fromEnv);
  }
  for (const plugin of loadPluginsFromDirectory(pluginDir)) {
    register(plugin);
  }

  router.get('/api/plugins', (_req: Request, res: Response) => {
    res.status(200).json({
      plugin_dir: pluginDir,
      plugin_path_env: process.env.PLUGIN_PATH || null,
      loaded: inventory,
    });
  });

  return router;
}

export default pluginRouter;
