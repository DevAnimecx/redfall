// Ensure the module VULN-034 loads exists before the suite runs.
//
// `dist/plugins/envplugin.js` is generated, not committed, because the whole
// point of that surface is that the loaded module is chosen by the environment
// rather than present in the source tree. But that means a clean checkout fails
// the suite with "Cannot find module" until something happens to run a build.
// Generating it here makes the failure impossible instead of incidental.
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const target = join(root, 'dist', 'plugins', 'envplugin.js');

if (!existsSync(target)) {
  execFileSync(process.execPath, [join(root, 'scripts', 'make_plugin.mjs')], { stdio: 'inherit' });
}
