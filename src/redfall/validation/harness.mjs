// Redfall exploit harness. Runs INSIDE the gVisor sandbox container.
//
// Responsibilities, in order:
//   1. start a real PostgreSQL instance
//   2. install and start the real target application
//   3. wait until the target answers on its health route
//   4. replay the PoC request(s) over real HTTP
//   5. evaluate the PoC predicate against the real response
//   6. print one JSON verdict on stdout, prefixed REDFALL_VERDICT
//
// Everything here talks to a live process over a real socket. Nothing in this
// file decides whether a vulnerability exists by reading source code.

import { readFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { execFileSync, spawn } from 'node:child_process';
import { createConnection } from 'node:net';
import { join, resolve } from 'node:path';

import { bindings, csvFields, detectTargetKind, evaluate, median, parseHttpResponse, parseRawRequest, prepareStepRequest, resolvePythonStart, runStepChain } from './harness_internals.mjs';

const WORK = resolve(process.env.REDFALL_WORK || '/work');
const TARGET = process.env.REDFALL_TARGET_DIR || 'target';
const POC_FILE = process.env.REDFALL_POC_FILE || 'poc.json';
const APP_PORT = Number(process.env.REDFALL_APP_PORT || '4000');
const PG_USER = process.env.REDFALL_PG_USER || 'vulnbank';
const PG_PASSWORD = process.env.REDFALL_PG_PASSWORD || 'Sup3rS3cretBankPwd!';
const PG_DATABASE = process.env.REDFALL_PG_DATABASE || 'vulnbank';
const READY_TIMEOUT_MS = Number(process.env.REDFALL_READY_TIMEOUT_MS || '180000');

const targetDir = join(WORK, TARGET);
const log = (...parts) => process.stderr.write(`[harness] ${parts.join(' ')}\n`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function emit(verdict) {
  process.stdout.write(`\nREDFALL_VERDICT ${JSON.stringify(verdict)}\n`);
}

function fail(reason, detail = '') {
  emit({ reproduced: false, reason, detail, status: null, body: '', evidence: '' });
  process.exit(0);
}

// ---------------------------------------------------------------- postgres
async function startPostgres() {
  const pgRoot = '/usr/lib/postgresql';
  if (!existsSync(pgRoot)) fail('postgres-not-found', 'no PostgreSQL server binaries in the sandbox image');
  const version = execFileSync('ls', [pgRoot], { encoding: 'utf8' }).trim().split('\n').sort().pop();
  const dataDir = '/tmp/redfall-pg';
  if (existsSync(dataDir)) execFileSync('rm', ['-rf', dataDir]);
  mkdirSync(dataDir, { recursive: true });
  execFileSync('chown', ['postgres:postgres', dataDir]);

  const run = (args) => execFileSync('su', ['postgres', '-c', args], { stdio: 'pipe', timeout: 120_000 });
  run(`${pgRoot}/${version}/bin/initdb -D ${dataDir} -A trust`);
  run(`${pgRoot}/${version}/bin/pg_ctl -D ${dataDir} -l /tmp/redfall-pg.log -w start`);
  const psql = `${pgRoot}/${version}/bin/psql`;
  run(`${psql} -d postgres -c "CREATE ROLE ${PG_USER} LOGIN PASSWORD '${PG_PASSWORD}' SUPERUSER;"`);
  run(`${psql} -d postgres -c "CREATE DATABASE ${PG_DATABASE} OWNER ${PG_USER};"`);
  log(`postgres ${version} ready`);
  return psql;
}

// ------------------------------------------------------------------ target
async function prepareDatabase() {
  const dbUrl = `postgresql://${PG_USER}:${PG_PASSWORD}@127.0.0.1:5432/${PG_DATABASE}`;
  for (const rel of ['migrations/001_init.sql', 'migrations/002_seed.sql']) {
    const file = join(targetDir, rel);
    if (existsSync(file)) {
      log(`applying ${rel}`);
      execFileSync('psql', [dbUrl, '-f', file], { cwd: targetDir, stdio: 'pipe', timeout: 120_000 });
    }
  }
  return dbUrl;
}

async function startTarget() {
  const files = readdirSync(targetDir);
  const kind = detectTargetKind(files);
  if (kind === 'python') return startPythonTarget(files);
  if (kind !== 'node') {
    fail('target-missing', `no package.json, requirements.txt, pyproject.toml or setup.py at ${targetDir}`);
  }

  if (!existsSync(join(targetDir, 'node_modules'))) {
    log('installing target dependencies');
    execFileSync('npm', ['install', '--no-audit', '--no-fund', '--loglevel=error'], {
      cwd: targetDir,
      stdio: 'pipe',
      timeout: 900_000,
    });
  }

  const dbUrl = await prepareDatabase();

  const uploadDir = '/tmp/redfall-uploads';
  mkdirSync(uploadDir, { recursive: true });
  const env = {
    ...process.env,
    NODE_ENV: 'test',
    PORT: String(APP_PORT),
    HOST: '0.0.0.0',
    DATABASE_URL: dbUrl,
    JWT_SECRET: process.env.REDFALL_JWT_SECRET || 'redfall-scan-secret-do-not-use-in-prod',
    DB_PASSWORD: PG_PASSWORD,
    STRIPE_WEBHOOK_SECRET: process.env.REDFALL_STRIPE_SECRET || 'whsec_redfall_scan_secret',
    UPLOAD_DIR: uploadDir,
  };

  log('starting target application');
  const child = spawn('npm', ['start'], { cwd: targetDir, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let bootLog = '';
  child.stdout.on('data', (d) => (bootLog += d.toString()));
  child.stderr.on('data', (d) => (bootLog += d.toString()));

  if (!(await waitForHealth())) {
    child.kill('SIGKILL');
    fail('target-did-not-start', bootLog.slice(-3000));
  }
  log('target is answering');
  return child;
}

/**
 * Python targets boot through the same contract the range targets use: a
 * virtualenv with the target's requirements, an explicit start command from
 * `redfall.target.json` (or a root `app.py`), and a real /health wait.
 */
async function startPythonTarget(files) {
  const configPath = join(targetDir, 'redfall.target.json');
  const config = existsSync(configPath) ? JSON.parse(readFileSync(configPath, 'utf8')) : null;
  const resolved = resolvePythonStart(config, { port: APP_PORT, rootHasAppPy: files.includes('app.py') });
  if (!resolved) {
    fail('target-missing', 'no redfall.target.json and no app.py: the Python boot contract is unknown');
  }

  const venv = '/tmp/redfall-pyvenv';
  const python = join(venv, 'bin', 'python');
  if (!existsSync(python)) {
    log('creating Python virtualenv');
    execFileSync('python3', ['-m', 'venv', venv], { stdio: 'pipe', timeout: 300_000 });
  }
  const pip = join(venv, 'bin', 'pip');
  if (files.includes('requirements.txt')) {
    log('installing target requirements');
    execFileSync(pip, ['install', '--disable-pip-version-check', '-q', '-r', 'requirements.txt'], {
      cwd: targetDir,
      stdio: 'pipe',
      timeout: 900_000,
    });
  } else if (files.includes('pyproject.toml') || files.includes('setup.py')) {
    log('installing target package');
    execFileSync(pip, ['install', '--disable-pip-version-check', '-q', '.'], {
      cwd: targetDir,
      stdio: 'pipe',
      timeout: 900_000,
    });
  }

  const dbUrl = await prepareDatabase();
  const uploadDir = '/tmp/redfall-uploads';
  mkdirSync(uploadDir, { recursive: true });
  const env = {
    ...process.env,
    PORT: String(APP_PORT),
    HOST: '0.0.0.0',
    DATABASE_URL: dbUrl,
    DB_PASSWORD: PG_PASSWORD,
    UPLOAD_DIR: uploadDir,
    ...resolved.env,
  };
  const cwd = resolved.cwd ? join(targetDir, resolved.cwd) : targetDir;

  log(`starting Python target: ${resolved.args.join(' ')}`);
  const child = spawn(python, resolved.args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let bootLog = '';
  child.stdout.on('data', (d) => (bootLog += d.toString()));
  child.stderr.on('data', (d) => (bootLog += d.toString()));

  if (!(await waitForHealth(resolved.health))) {
    child.kill('SIGKILL');
    fail('target-did-not-start', bootLog.slice(-3000));
  }
  log('target is answering');
  return child;
}

async function waitForHealth(healthPath = '/health') {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try {
      const res = await httpRequest({ method: 'GET', path: healthPath, headers: {} }, '');
      if (res.status > 0) return true;
    } catch {
      /* not listening yet */
    }
    await sleep(500);
  }
  return false;
}

// -------------------------------------------------------------------- http
function httpRequest(req, body) {
  return new Promise((resolvePromise, reject) => {
    const started = Date.now();
    const conn = createConnection({ host: '127.0.0.1', port: APP_PORT }, () => {
      const head = [`${req.method} ${req.path} HTTP/1.1`, `Host: 127.0.0.1:${APP_PORT}`, 'Connection: close'];
      const lower = new Set(Object.keys(req.headers || {}).map((k) => k.toLowerCase()));
      for (const [k, v] of Object.entries(req.headers || {})) {
        if (k.toLowerCase() === 'host' || k.toLowerCase() === 'connection') continue;
        head.push(`${k}: ${v}`);
      }
      if (body && !lower.has('content-length')) head.push(`Content-Length: ${Buffer.byteLength(body)}`);
      conn.write(`${head.join('\r\n')}\r\n\r\n${body}`);
    });
    conn.setTimeout(30_000, () => conn.destroy(new Error('request timed out')));
    let raw = '';
    conn.on('data', (d) => (raw += d.toString('binary')));
    conn.on('error', reject);
    conn.on('close', () => {
      const sep = raw.indexOf('\r\n\r\n');
      const headText = sep === -1 ? raw : raw.slice(0, sep);
      const bodyBuf = Buffer.from(sep === -1 ? '' : raw.slice(sep + 4), 'binary');
      resolvePromise({ ...parseHttpResponse(headText, bodyBuf), elapsed_ms: Date.now() - started });
    });
  });
}

async function send(rawRequest) {
  const req = parseRawRequest(rawRequest);
  return httpRequest(req, req.body);
}

/**
 * Send a chain step. The step request is prepared by `prepareStepRequest`,
 * which recomputes the Content-Length the substitution invalidated.
 */
async function sendStep(rawRequest) {
  const req = prepareStepRequest(rawRequest);
  return httpRequest({ method: req.method, path: req.path, headers: req.headers }, req.body);
}

function psqlQuery(sql, psqlBin) {
  try {
    return execFileSync(
      psqlBin,
      [`postgresql://${PG_USER}:${PG_PASSWORD}@127.0.0.1:5432/${PG_DATABASE}`, '-tA', '-c', String(sql)],
      { encoding: 'utf8', timeout: 15_000 },
    ).trim();
  } catch (err) {
    return `ERROR ${err.message}`;
  }
}

function metadataReachable() {
  return new Promise((resolvePromise) => {
    const sock = createConnection({ host: '169.254.169.254', port: 80 }, () => {
      sock.destroy();
      resolvePromise(true);
    });
    sock.setTimeout(1500, () => {
      sock.destroy();
      resolvePromise(false);
    });
    sock.on('error', () => resolvePromise(false));
  });
}

// -------------------------------------------------------------------- poc
async function runPoc(poc, psqlBin) {
  if (Array.isArray(poc.steps) && poc.steps.length > 0) return runChain(poc, psqlBin);
  return runSingle(poc, psqlBin);
}

async function runSingle(poc, psqlBin) {
  const evidence = [];
  let setupStatus = null;

  if (poc.setup && poc.setup.request) {
    const setupRes = await send(poc.setup.request);
    setupStatus = setupRes.status;
    evidence.push(`setup -> ${setupRes.status} ${setupRes.body.slice(0, 400)}`);
    if (poc.setup.expect_expr) {
      const ok = evaluate(poc.setup.expect_expr, bindings(setupRes, { setup_status: setupStatus }, (s) => psqlQuery(s, psqlBin)));
      evidence.push(`setup predicate ${ok ? 'held' : 'did NOT hold'}`);
      if (!ok) return verdict(false, 'setup-precondition-failed', setupRes, evidence);
    }
  }

  const samples = await timedSamples(poc.request, poc.timing_samples || 1);
  const res = samples.results[samples.results.length - 1];
  evidence.push(`request -> ${res.status} ${res.body.slice(0, 600)}`);

  let followup = null;
  if (poc.followup && poc.followup.request) {
    followup = await send(poc.followup.request);
    evidence.push(`followup -> ${followup.status} ${followup.body.slice(0, 400)}`);
  }

  const probe = {
    setup_status: setupStatus,
    median_ms: median(samples.results.map((r) => r.elapsed_ms)),
    min_ms: Math.min(...samples.results.map((r) => r.elapsed_ms)),
    max_ms: Math.max(...samples.results.map((r) => r.elapsed_ms)),
    metadata_port: await metadataReachable(),
    samples: samples.results.length,
  };

  const query = (s) => psqlQuery(s, psqlBin);
  let ok;
  try {
    ok = evaluate(poc.expect_expr, bindings(res, { probe, followup, followup_status: followup ? followup.status : null }, query));
  } catch (err) {
    return { ...verdict(false, 'predicate-error', res, evidence), detail: `${err.name}: ${err.message}` };
  }

  if (poc.followup && poc.followup.expect_expr) {
    const followupOk = evaluate(poc.followup.expect_expr, bindings(followup, { probe }, query));
    evidence.push(`followup predicate ${followupOk ? 'held' : 'did NOT hold'}`);
    ok = ok === true && followupOk === true;
  }

  return verdict(ok === true, ok === true ? 'predicate-held' : 'predicate-failed', res, evidence);
}

/**
 * A chain PoC: several requests in order, where an earlier response supplies a
 * value a later request depends on. The chain is reproduced only when every
 * step's own predicate holds against the live application; the number of steps
 * that held is reported so a caller can credit only the joins it watched happen.
 */
async function runChain(poc, psqlBin) {
  const query = (s) => psqlQuery(s, psqlBin);

  const runHook = async (spec, index, ctx, label) => {
    const res = await sendStep(ctx.substitute(spec.request));
    let ok = true;
    let message = '';
    if (spec.expect_expr) {
      try {
        const extra = label === 'setup' ? { setup_status: res.status } : { followup_status: res.status };
        ok = evaluate(spec.expect_expr, bindings(res, { ...extra, values: ctx.values, step: index + 1 }, query)) === true;
      } catch (err) {
        ok = false;
        message = `${err.name}: ${err.message}`;
      }
    }
    return {
      ok,
      res,
      message,
      evidence: `step ${index + 1} ${label} -> ${res.status} ${res.body.slice(0, 400)}`,
    };
  };

  const outcome = await runStepChain(poc.steps, {
    send: sendStep,
    psql: query,
    extra: {
      expectExpr: poc.expect_expr,
      probe: { metadata_port: await metadataReachable(), samples: 1 },
    },
    hooks: {
      before: (step, index, ctx) => (step.setup && step.setup.request ? runHook(step.setup, index, ctx, 'setup') : null),
      after: (step, index, ctx) => (step.followup && step.followup.request ? runHook(step.followup, index, ctx, 'followup') : null),
    },
  });

  const res = outcome.last;
  const evidence = outcome.evidence;
  let reason = 'chain-reproduced';
  if (!outcome.ok) {
    const failure = outcome.failure || {};
    reason = failure.step === null || failure.step === undefined ? 'chain-failed' : `step-${failure.step + 1}-${failure.kind}`;
    if (failure.message) evidence.push(`failure: ${failure.message}`);
  }

  return {
    reproduced: outcome.ok === true,
    reason,
    detail: evidence.join('\n'),
    status: res ? res.status : null,
    body: res ? res.body.slice(0, 2000) : '',
    evidence: evidence.join('\n'),
    steps_passed: outcome.stepsPassed,
    steps: outcome.steps,
    values: outcome.values,
  };
}

function verdict(reproduced, reason, res, evidence) {
  return {
    reproduced,
    reason,
    detail: evidence.join('\n'),
    status: res ? res.status : null,
    body: res ? res.body.slice(0, 2000) : '',
    evidence: evidence.join('\n'),
  };
}

async function timedSamples(rawRequest, count) {
  const results = [];
  for (let i = 0; i < Math.max(1, count); i += 1) {
    results.push(await send(rawRequest));
  }
  return { results };
}

// ------------------------------------------------------------------- main
async function main() {
  const pocPath = join(WORK, POC_FILE);
  if (!existsSync(pocPath)) fail('poc-missing', `no PoC file at ${pocPath}`);
  const poc = JSON.parse(readFileSync(pocPath, 'utf8'));
  const isChain = Array.isArray(poc.steps) && poc.steps.length > 0;
  if (!isChain && !poc.request) fail('poc-malformed', 'PoC has neither `steps` nor `request`');
  if (!poc.expect_expr) fail('poc-malformed', 'PoC has no `expect_expr`');
  if (isChain) {
    for (const [index, step] of poc.steps.entries()) {
      if (!step || typeof step.request !== 'string' || !step.request) {
        fail('poc-malformed', `step ${index + 1} has no \`request\``);
      }
      if (typeof step.expect_expr !== 'string' || !step.expect_expr) {
        fail('poc-malformed', `step ${index + 1} has no \`expect_expr\``);
      }
    }
  }

  const psqlBin = await startPostgres();
  const target = await startTarget();
  const result = await runPoc(poc, psqlBin);
  target.kill('SIGKILL');
  emit(result);
  process.exit(0);
}

main().catch((err) => {
  fail('harness-error', err && err.stack ? err.stack : String(err));
});
