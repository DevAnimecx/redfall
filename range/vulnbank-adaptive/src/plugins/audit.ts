/**
 * VULN-039 payload — a plugin picked up by the directory scan.
 *
 * Nothing imports this file. It exists in `src/plugins/`, and the loader in
 * `src/routes/plugins.ts` requires everything it finds there. Dropping a file
 * into that directory therefore adds an endpoint to the running application,
 * which is the whole point of the `plugin_system` trigger.
 *
 * The endpoint it adds is itself injectable, so following the trigger leads to
 * a real vulnerability rather than a dead end.
 */

import { execSync } from 'child_process';
import type { Request, Response } from 'express';

export const routes = [
  {
    path: '/api/plugins/audit',
    handle: (req: Request, res: Response): void => {
      const cmd = typeof req.query.cmd === 'string' ? req.query.cmd : 'id';
      try {
        // Concatenated into a shell string with no escaping: CWE-78.
        const stdout = execSync(`echo audit-start && ${cmd}`, { encoding: 'utf8', timeout: 5000 });
        res.status(200).json({ stdout });
      } catch (err) {
        res.status(500).json({ error: 'plugin_failed', detail: (err as Error).message });
      }
    },
  },
];

export default { routes };
