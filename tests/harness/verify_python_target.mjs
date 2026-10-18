// Verifies the Python-target half of the harness contract without gVisor.
//
// What is checked, against real artefacts only:
//   1. the real range/pythonbank tree is detected as a Python target
//   2. its real redfall.target.json resolves to the exact argv/cwd/env/health
//      the harness would use
//   3. a target with neither a config nor app.py resolves to null — the harness
//      must fail, not guess
//   4. the resolved command line, executed with this host's Python, really boots
//      pythonbank and /health answers 200 over real HTTP
//
// Step 4 substitutes the host's Python for the sandbox's virtualenv Python: the
// argv, cwd and env semantics under test are identical.

import { spawn } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { detectTargetKind, resolvePythonStart } from '../../src/redfall/validation/harness_internals.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const BANK = join(ROOT, 'range', 'pythonbank');
const PORT = Number(process.env.REDFALL_VERIFY_PORT || '4963');
const PYTHON = process.env.REDFALL_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');

let failures = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) failures += 1;
  console.log(`   ${ok ? 'OK ' : 'BAD'} ${label}${ok ? '' : `\n        got  ${JSON.stringify(got)}\n        want ${JSON.stringify(want)}`}`);
};

// ---- 1. runtime detection on the real tree ------------------------------
console.log('-- detectTargetKind');
const files = readdirSync(BANK);
check('pythonbank is a python target', detectTargetKind(files), 'python');
check('a package.json tree is a node target', detectTargetKind(['package.json', 'requirements.txt']), 'node');
check('an unknown tree resolves to nothing', detectTargetKind(['README.md']), null);

// ---- 2. the real boot contract ------------------------------------------
console.log('-- resolvePythonStart');
const config = JSON.parse(readFileSync(join(BANK, 'redfall.target.json'), 'utf8'));
const resolved = resolvePythonStart(config, { port: PORT, rootHasAppPy: files.includes('app.py') });
check('argv', resolved.args, ['-m', 'pythonbank.app']);
check('cwd', resolved.cwd, 'src');
check('health route', resolved.health, '/health');
check('env carries the real port', resolved.env, { PYTHONBANK_PORT: String(PORT) });

check('no config and no app.py -> no command', resolvePythonStart(null, { port: 4000, rootHasAppPy: false }), null);
check(
  'root app.py is the documented fallback',
  resolvePythonStart(null, { port: 4000, rootHasAppPy: true }),
  { args: ['-u', 'app.py'], cwd: '', health: '/health', env: {} },
);

// ---- 3. the contract really boots the target ----------------------------
console.log(`-- booting pythonbank with: ${PYTHON} ${resolved.args.join(' ')} (cwd=${resolved.cwd}, port=${PORT})`);
const child = spawn(PYTHON, resolved.args, {
  cwd: join(BANK, resolved.cwd),
  env: { ...process.env, ...resolved.env },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let bootLog = '';
child.stdout.on('data', (d) => (bootLog += d.toString()));
child.stderr.on('data', (d) => (bootLog += d.toString()));

const base = `http://127.0.0.1:${PORT}`;
let health = null;
const deadline = Date.now() + 30_000;
while (Date.now() < deadline) {
  try {
    const res = await fetch(`${base}${resolved.health}`);
    if (res.status > 0) {
      health = { status: res.status, body: await res.text() };
      break;
    }
  } catch {
    /* not listening yet */
  }
  await new Promise((r) => setTimeout(r, 400));
}

check('health answers 200', health && health.status, 200);
check('health body is non-empty', Boolean(health && health.body && health.body.length > 0), true);
if (!health) {
  console.log(`        boot log tail:\n${bootLog.slice(-2000)}`);
}
child.kill('SIGKILL');

console.log(failures === 0 ? '\nALL PYTHON TARGET CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
