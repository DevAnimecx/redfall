import { Router } from 'express';
import fs from 'fs';
import path from 'path';
import pool from '../db';
import { requireAdmin, requireAuth, AuthedRequest } from '../middleware/auth';
import { PLUGIN_DIR } from './documents';

const router = Router();

export interface LoadedPlugin {
  name: string;
  loaded_at: string;
  marker?: string;
}

const loaded: LoadedPlugin[] = [];

/**
 * CHN-03, step B — reload executes whatever is in the plugin directory.
 *
 * `require()` on a path compiles and runs the file. There is no signature check,
 * no allow-list and no sandbox, so the upload in `documents.ts` becomes code
 * execution as soon as this route is called. The route is admin-only, which is
 * exactly why it needs the previous chain step to reach.
 */
router.post('/reload', requireAuth, requireAdmin, async (req: AuthedRequest, res) => {
  if (!fs.existsSync(PLUGIN_DIR)) {
    res.json({ loaded: [], note: 'plugin_dir_missing' });
    return;
  }
  const names: string[] = [];
  for (const entry of fs.readdirSync(PLUGIN_DIR)) {
    if (!entry.endsWith('.js')) {
      continue;
    }
    const full = path.join(PLUGIN_DIR, entry);
    try {
      const mod = require(full) as { name?: string; marker?: string };
      loaded.push({
        name: mod.name || entry,
        loaded_at: new Date().toISOString(),
        marker: mod.marker,
      });
      names.push(entry);
    } catch (err) {
      loaded.push({ name: entry, loaded_at: new Date().toISOString() });
    }
  }
  await pool.query(
    `INSERT INTO audit_log (actor, action, detail) VALUES ($1, 'plugins_reloaded', $2)`,
    [req.user?.username || 'anonymous', names.join(',') || 'none'],
  );
  res.json({ loaded, files_executed: names });
});

router.get('/', requireAuth, async (_req, res) => {
  res.json({ plugin_dir: PLUGIN_DIR, loaded, dir_contents: fs.readdirSync(PLUGIN_DIR) });
});

export default router;
