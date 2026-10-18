/* eslint-disable no-console */
/**
 * apply_patch.ts — applies or reverts a known-good patch from patches/.
 *
 *   npx ts-node scripts/apply_patch.ts <VULN-ID> [<VULN-ID> ...]
 *   npx ts-node scripts/apply_patch.ts --revert <VULN-ID> [<VULN-ID> ...]
 *
 * Uses `patch` (not `git apply`) so it works outside a git working tree, which is
 * how range-runner invokes it against a freshly checked-out target.
 */
import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const ROOT = path.resolve(__dirname, '..');

function runPatch(patchFile: string, revert: boolean): { ok: boolean; output: string } {
  const args = ['-p1', '--no-backup-if-mismatch', '--batch'];
  if (revert) args.unshift('-R');
  args.push('-i', patchFile);
  try {
    const output = execFileSync('patch', args, { cwd: ROOT, encoding: 'utf8', timeout: 30000 });
    return { ok: true, output };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; message: string };
    return { ok: false, output: `${e.stdout || ''}${e.stderr || ''}${e.message}` };
  }
}

function main(): void {
  const argv = process.argv.slice(2);
  const revert = argv.includes('--revert');
  const ids = argv.filter((a) => !a.startsWith('--'));

  if (ids.length === 0) {
    console.error('usage: apply_patch.ts [--revert] <VULN-ID> [...]');
    process.exit(2);
  }

  let failed = 0;
  for (const id of ids) {
    const patchFile = path.join(ROOT, 'patches', `${id}.diff`);
    if (!fs.existsSync(patchFile)) {
      console.log(`${revert ? 'REVERT-FAILED' : 'APPLY-FAILED'}  ${id}  no patch file at patches/${id}.diff`);
      failed += 1;
      continue;
    }
    const result = runPatch(patchFile, revert);
    // A patch that only lands with fuzz or an offset does not match its target.
    // Treating that as success silently produced a "fixed" file that was not
    // fixed, so it is a hard failure instead.
    const fuzzy = /with fuzz|offset \d+ line|Reversed \(or previously applied\)|Unreversed patch detected/.test(
      result.output,
    );
    const ok = result.ok && !fuzzy;
    const label = revert ? (ok ? 'REVERTED' : 'REVERT-FAILED') : ok ? 'APPLIED' : 'APPLY-FAILED';
    const note = fuzzy && result.ok ? ' (rejected: applied with fuzz/offset, patch does not match target)' : '';
    console.log(`${label}  ${id}  ${result.output.trim().split('\n').filter(Boolean).join(' | ')}${note}`);
    if (!ok) failed += 1;
  }

  process.exit(failed === 0 ? 0 : 1);
}

main();
