// Emit the module that VULN-034's `require(process.env.PLUGIN_PATH)` loads.
//
// It is generated rather than committed because the whole point of that surface
// is that the loaded module is chosen by the environment, not by the source
// tree. Run by `npm run build` via postbuild so dist/ is self-contained.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'plugins');
mkdirSync(dist, { recursive: true });

const source = `'use strict';
// VULN-034 payload. Loaded only because PLUGIN_PATH named it.
const { execSync } = require('child_process');

exports.routes = [
  {
    path: '/api/plugins/envinfo',
    handle: (req, res) => {
      try {
        // The argument reaches a shell unescaped: CWE-78.
        const stdout = execSync('echo envplugin-loaded && id', { encoding: 'utf8' });
        res.status(200).json({ stdout, loaded_via: 'PLUGIN_PATH' });
      } catch (err) {
        res.status(500).json({ error: 'envplugin_failed', detail: err.message });
      }
    },
  },
];
`;

writeFileSync(join(dist, 'envplugin.js'), source);
console.log(`make-plugin: wrote ${join(dist, 'envplugin.js')}`);
