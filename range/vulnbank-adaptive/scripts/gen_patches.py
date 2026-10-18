#!/usr/bin/env python3
"""Generates the known-good patches in patches/ by diffing real file edits.

For every vulnerability this script:
  1. writes the fixed source (and any test change the fix requires) to disk,
  2. runs `git diff --no-index` between the pristine copy and the edited copy to
     produce a real unified diff,
  3. restores the pristine copy.

Nothing here is hand-written diff text: every .diff is the output of git diff on
an edit that was actually applied and actually reverted.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Each fix is a list of (relative_path, old_text, new_text) replacements.
FIXES: dict[str, list[tuple[str, str, str]]] = {}


def fix(vuln_id: str, *edits: tuple[str, str, str]) -> None:
    FIXES[vuln_id] = list(edits)


# ---------------------------------------------------------------- auth.ts -----
fix(
    "VULN-001",
    (
        "src/routes/auth.ts",
        """  const lookup = `SELECT id, username, password, email, role, balance
                  FROM users
                  WHERE username = '${username}'`;
  pool
    .query(lookup)""",
        """  const lookup = `SELECT id, username, password, email, role, balance
                  FROM users
                  WHERE username = $1`;
  pool
    .query(lookup, [username])""",
    ),
)

fix(
    "VULN-002",
    (
        "src/routes/auth.ts",
        "const router = Router();",
        """const router = Router();

// VULN-002 fix: a fixed-window limiter on the credential endpoint. Counts attempts
// per source address and answers 429 once the window budget is spent.
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 8;
const loginAttempts = new Map<string, { count: number; resetAt: number }>();

function loginRateLimit(req: Request, res: Response, next: () => void): void {
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (entry && entry.resetAt > now && entry.count >= LOGIN_MAX_ATTEMPTS) {
    res.status(429).json({ error: 'too_many_attempts', retry_after_ms: entry.resetAt - now });
    return;
  }

  // Only failed attempts are charged, so a user who knows their password is never
  // locked out by their own successful logins.
  const chargeFailure = (): void => {
    const current = loginAttempts.get(key);
    if (!current || current.resetAt <= Date.now()) {
      loginAttempts.set(key, { count: 1, resetAt: Date.now() + LOGIN_WINDOW_MS });
      return;
    }
    current.count += 1;
  };

  res.on('finish', () => {
    if (res.statusCode === 401) chargeFailure();
  });
  next();
}""",
    ),
    (
        "src/routes/auth.ts",
        "router.post('/login', loginHandler);",
        "router.post('/login', loginRateLimit, loginHandler);",
    ),
)

fix(
    "VULN-003",
    (
        "src/routes/auth.ts",
        """        res.status(401).json({ error: 'no such user', field: 'username' });
        return;
      }
      if (!verifyPassword(password, row.password)) {
        res.status(401).json({ error: 'wrong password', field: 'password' });
        return;
      }""",
        """        res.status(401).json({ error: 'invalid_credentials' });
        return;
      }
      if (!verifyPassword(password, row.password)) {
        res.status(401).json({ error: 'invalid_credentials' });
        return;
      }""",
    ),
    (
        "tests/auth.test.ts",
        """      expect(res.status).toBe(401);
      expect(res.body.error).toBe('wrong password');""",
        """      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_credentials');""",
    ),
    (
        "tests/auth.test.ts",
        """      expect(res.status).toBe(401);
      expect(res.body.error).toBe('no such user');""",
        """      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_credentials');""",
    ),
)

fix(
    "VULN-004",
    (
        "src/routes/auth.ts",
        """      const row = result.rows[0];
      if (!row) {""",
        """      const row = result.rows[0];
      if (!row) {
        // VULN-004 fix: run the same verification against a decoy hash so the
        // unknown-user path costs the same as the real one.
        verifyPassword(password, DUMMY_HASH);""",
    ),
    (
        "src/routes/auth.ts",
        "const router = Router();",
        """const router = Router();

// A precomputed hash of an unusable password, used to equalise response time
// between the unknown-user and wrong-password paths (VULN-004 fix).
const DUMMY_HASH = hashPassword('redfall-decoy-password-never-valid');""",
    ),
)

fix(
    "VULN-007",
    (
        "src/routes/auth.ts",
        """  const fields: Record<string, unknown> = { ...body };
  delete fields.password;
  // Hashed with the same MD5 helper login verifies against (VULN-029).
  const columns = ['username', 'email', ...Object.keys(fields).filter((k) => k !== 'username' && k !== 'email')];
  const placeholders = columns.map((_c, i) => `$${i + 1}`);
  const values = columns.map((c) => (c === 'username' ? username : c === 'email' ? email : fields[c]));

  pool
    .query(
      `INSERT INTO users (${columns.join(', ')}, password)
       VALUES (${placeholders.join(', ')}, $${columns.length + 1})
       RETURNING id, username, email, role, balance, kyc_complete`,
      [...values, hashPassword(password)],
    )""",
        """  // VULN-007 fix: only caller-controlled columns are written; privileged fields
  // are set by the server, never taken from the request body.
  pool
    .query(
      `INSERT INTO users (username, email, password, role, balance, kyc_complete)
       VALUES ($1, $2, $3, 'customer', 0, false)
       RETURNING id, username, email, role, balance, kyc_complete`,
      [username, email, hashPassword(password)],
    )""",
    ),
)

# ------------------------------------------------------------- middleware -----
fix(
    "VULN-005",
    (
        "src/middleware/jwt.ts",
        "  return jwt.verify(token, JWT_SECRET) as Record<string, unknown>;",
        "  return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }) as Record<string, unknown>;",
    ),
)

fix(
    "VULN-006",
    (
        "src/middleware/jwt.ts",
        "  return jwt.sign(payload, JWT_SECRET);",
        "  return jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });",
    ),
)

fix(
    "VULN-027",
    (
        "src/middleware/jwt.ts",
        "// VULN-027: hardcoded JWT signing secret committed to source (CWE-798).\nconst JWT_SECRET = 'vulnbank-dev-secret-do-not-ship'; // line 3 — hardcoded_jwt_secret",
        "// VULN-027 fix: the signing secret comes from the environment and the process\n// refuses to start without it, so no secret lives in source control.\nconst JWT_SECRET = process.env.JWT_SECRET;\nif (!JWT_SECRET) {\n  throw new Error('JWT_SECRET must be set in the environment');\n}",
    ),
    (
        "tests/globalSetup.ts",
        "  process.env.DATABASE_URL =",
        "  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-only-jwt-secret-value';\n  process.env.DATABASE_URL =",
    ),
    (
        "tests/jest.setup.ts",
        "process.env.DATABASE_URL =",
        "process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-only-jwt-secret-value';\nprocess.env.DATABASE_URL =",
    ),
)

# ----------------------------------------------------------------- users ------
fix(
    "VULN-008",
    (
        "src/routes/users.ts",
        """// VULN-008: the caller supplies :id and the handler never compares it against the
// authenticated identity, so any token can read any account (CWE-639).
router.get('/:id', requireAuth, (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: 'invalid_id' });
    return;
  }""",
        """// VULN-008: the caller supplies :id and the handler never compares it against the
// authenticated identity, so any token can read any account (CWE-639).
router.get('/:id', requireAuth, (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: 'invalid_id' });
    return;
  }
  // VULN-008 fix: a public profile stays readable, but the sensitive account
  // fields are only returned to the owner or an admin.
  const isSelfOrAdmin = id === req.user!.id || req.user!.role === 'admin';""",
    ),
    (
        "src/routes/users.ts",
        """      res.status(200).json({ user: result.rows[0] });""",
        """      const user = { ...result.rows[0] } as Record<string, unknown>;
      if (!isSelfOrAdmin) {
        delete user.email;
        delete user.balance;
        delete user.kyc_complete;
        delete user.role;
      }
      res.status(200).json({ user });""",
    ),
    (
        "tests/users.test.ts",
        """    it('returns the requested user', async () => {
      const res = await request(app).get('/api/users/1').set('Authorization', auth(token));
      expect(res.status).toBe(200);
      expect(res.body.user.username).toBe('admin');
      expect(res.body.user.email).toBe('admin@vulnbank.test');
    });""",
        """    it('returns the requested user', async () => {
      const res = await request(app).get('/api/users/1').set('Authorization', auth(token));
      expect(res.status).toBe(200);
      expect(res.body.user.username).toBe('admin');
    });

    it('hides another account balance and email from a non-owner', async () => {
      const res = await request(app).get('/api/users/1').set('Authorization', auth(token));
      expect(res.status).toBe(200);
      expect(res.body.user.balance).toBeUndefined();
      expect(res.body.user.email).toBeUndefined();
    });

    it('shows the full record to the owner', async () => {
      const res = await request(app).get('/api/users/2').set('Authorization', auth(token));
      expect(res.status).toBe(200);
      expect(res.body.user.email).toBe('alice@vulnbank.test');
      expect(res.body.user.balance).toBeDefined();
    });""",
    ),
)

fix(
    "VULN-009",
    (
        "src/routes/users.ts",
        """  const limitRaw = req.query.limit;
  const limit = limitRaw === undefined ? 25 : Number(limitRaw);
  if (!Number.isFinite(limit) || limit < 0) {
    res.status(400).json({ error: 'invalid_limit' });
    return;
  }""",
        """  const limitRaw = req.query.limit;
  const requested = limitRaw === undefined ? 25 : Number(limitRaw);
  if (!Number.isFinite(requested) || requested < 0) {
    res.status(400).json({ error: 'invalid_limit' });
    return;
  }
  // VULN-009 fix: the page size is capped so one request cannot dump the table.
  const MAX_PAGE_SIZE = 100;
  const limit = Math.min(requested, MAX_PAGE_SIZE);""",
    ),
    (
        "tests/users.test.ts",
        """    it('honours an explicit limit', async () => {
      const res = await request(app).get('/api/users?limit=2').set('Authorization', auth(token));
      expect(res.status).toBe(200);
      expect(res.body.count).toBe(2);
    });""",
        """    it('honours an explicit limit', async () => {
      const res = await request(app).get('/api/users?limit=2').set('Authorization', auth(token));
      expect(res.status).toBe(200);
      expect(res.body.count).toBe(2);
    });

    it('caps an oversized limit', async () => {
      const res = await request(app).get('/api/users?limit=1000000').set('Authorization', auth(token));
      expect(res.status).toBe(200);
      expect(res.body.limit).toBeLessThanOrEqual(100);
    });""",
    ),
)

fix(
    "VULN-010",
    (
        "src/routes/users.ts",
        """    const rows = result.rows.map((r) => `<li>${r.id} — ${r.username}</li>`).join('');""",
        """    const rows = result.rows.map((r) => `<li>${escapeHtml(String(r.id))} — ${escapeHtml(r.username)}</li>`).join('');""",
    ),
    (
        "src/routes/users.ts",
        """        `<html><body><h1>Search results for: ${q}</h1><ul>${rows}</ul>` +""",
        """        `<html><body><h1>Search results for: ${escapeHtml(q)}</h1><ul>${rows}</ul>` +""",
    ),
    (
        "src/routes/users.ts",
        "const router = Router();",
        """const router = Router();

// VULN-010 fix: HTML-encode every value interpolated into a response body.
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}""",
    ),
)

# ---------------------------------------------------------------- profile -----
fix(
    "VULN-011",
    (
        "src/routes/profile.ts",
        """        `<html><body><h2>${p.username}</h2><div class="bio">${p.bio}</div>` +
          `<a href="${p.website}">${p.display_name}</a></body></html>`,""",
        """        `<html><body><h2>${escapeHtml(p.username)}</h2><div class="bio">${escapeHtml(p.bio)}</div>` +
          `<a href="${escapeHtml(p.website)}">${escapeHtml(p.display_name)}</a></body></html>`,""",
    ),
    (
        "src/routes/profile.ts",
        "const router = Router();",
        """const router = Router();

// VULN-011 fix: stored content is encoded at render time.
function escapeHtml(value: string): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}""",
    ),
)

fix(
    "VULN-012",
    (
        "src/routes/profile.ts",
        """    const e = err as { message: string; stack?: string; code?: string; query?: string };
    res.status(500).json({
      error: 'profile_lookup_failed',
      message: e.message,
      code: e.code,
      stack: e.stack,
      query: e.query,
    });""",
        """    // VULN-012 fix: log internally, return an opaque error to the caller.
    console.error('[profile] lookup failed', err);
    res.status(500).json({ error: 'profile_lookup_failed' });""",
    ),
)

# --------------------------------------------------------------------- tx -----
fix(
    "VULN-013",
    (
        "src/routes/tx.ts",
        """  try {
    const meRow = await pool.query(`SELECT balance FROM users WHERE id = $1`, [me]);
    if (meRow.rowCount === 0) {
      res.status(404).json({ error: 'sender_not_found' });
      return;
    }
    const peerRow = await pool.query(`SELECT id FROM users WHERE id = $1`, [to]);
    if (peerRow.rowCount === 0) {
      res.status(404).json({ error: 'recipient_not_found' });
      return;
    }

    const balance = Number(meRow.rows[0].balance);
    // Check-then-act with a gap in between: the window the race exploits.
    await sleep(120);

    if (amount > 0 && balance < amount) {
      res.status(400).json({ error: 'insufficient_funds', balance });
      return;
    }

    await pool.query(`UPDATE users SET balance = balance - $1 WHERE id = $2`, [amount, me]);
    await pool.query(`UPDATE users SET balance = balance + $1 WHERE id = $2`, [amount, to]);
    const tx = await pool.query(
      `INSERT INTO transactions (owner_id, kind, counterparty, amount, note)
       VALUES ($1, 'transfer', $2, $3, $4) RETURNING id, owner_id, kind, counterparty, amount, note`,
      [me, String(to), amount, note],
    );

    const after = await pool.query(`SELECT balance FROM users WHERE id = $1`, [me]);
    res.status(201).json({ transaction: tx.rows[0], balance_after: Number(after.rows[0].balance) });
  } catch (err) {
    res.status(500).json({ error: 'transfer_failed', detail: (err as Error).message });
  }""",
        """  // VULN-013 fix: the check and the writes happen inside one transaction and the
  // sender row is locked, so concurrent transfers serialise instead of racing.
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const meRow = await client.query(`SELECT balance FROM users WHERE id = $1 FOR UPDATE`, [me]);
    if (meRow.rowCount === 0) {
      await client.query('ROLLBACK');
      res.status(404).json({ error: 'sender_not_found' });
      return;
    }
    const peerRow = await client.query(`SELECT id FROM users WHERE id = $1 FOR UPDATE`, [to]);
    if (peerRow.rowCount === 0) {
      await client.query('ROLLBACK');
      res.status(404).json({ error: 'recipient_not_found' });
      return;
    }

    const balance = Number(meRow.rows[0].balance);
    if (amount > 0 && balance < amount) {
      await client.query('ROLLBACK');
      res.status(400).json({ error: 'insufficient_funds', balance });
      return;
    }

    await client.query(`UPDATE users SET balance = balance - $1 WHERE id = $2`, [amount, me]);
    await client.query(`UPDATE users SET balance = balance + $1 WHERE id = $2`, [amount, to]);
    const tx = await client.query(
      `INSERT INTO transactions (owner_id, kind, counterparty, amount, note)
       VALUES ($1, 'transfer', $2, $3, $4) RETURNING id, owner_id, kind, counterparty, amount, note`,
      [me, String(to), amount, note],
    );

    const after = await client.query(`SELECT balance FROM users WHERE id = $1`, [me]);
    await client.query('COMMIT');
    res.status(201).json({ transaction: tx.rows[0], balance_after: Number(after.rows[0].balance) });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'transfer_failed', detail: (err as Error).message });
  } finally {
    client.release();
  }""",
    ),
)

fix(
    "VULN-014",
    (
        "src/routes/tx.ts",
        """  if (!Number.isFinite(amount) || amount === 0) {
    res.status(400).json({ error: 'invalid_amount' });
    return;
  }""",
        """  // VULN-014 fix: only positive amounts are accepted, so a transfer cannot be
  // reversed to credit the sender.
  if (!Number.isFinite(amount) || amount <= 0) {
    res.status(400).json({ error: 'invalid_amount' });
    return;
  }""",
    ),
)

fix(
    "VULN-015",
    (
        "src/routes/tx.ts",
        """router.get('/:id', requireAuth, async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: 'invalid_id' });
    return;
  }""",
        """router.get('/:id', requireAuth, async (req: AuthedRequest, res: Response) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    res.status(400).json({ error: 'invalid_id' });
    return;
  }
  // VULN-015 fix: scope the lookup to the caller's own transactions.
  const ownerClause = req.user!.role === 'admin' ? '' : 'AND t.owner_id = $2';""",
    ),
    (
        "src/routes/tx.ts",
        """       FROM transactions t JOIN users u ON u.id = t.owner_id
       WHERE t.id = $1`,
      [id],
    );""",
        """       FROM transactions t JOIN users u ON u.id = t.owner_id
       WHERE t.id = $1 ${ownerClause}`,
      req.user!.role === 'admin' ? [id] : [id, req.user!.id],
    );""",
    ),
    (
        "tests/transactions.test.ts",
        """    it('returns a transaction by id', async () => {
      const listed = await pool.query(`SELECT id FROM transactions ORDER BY id LIMIT 1`);
      const res = await request(app)
        .get(`/api/transactions/${listed.rows[0].id}`)
        .set('Authorization', auth(bob));
      expect(res.status).toBe(200);
      expect(res.body.transaction.id).toBe(listed.rows[0].id);
    });""",
        """    it('returns the caller\\'s own transaction by id', async () => {
      const listed = await pool.query(
        `SELECT t.id FROM transactions t JOIN users u ON u.id = t.owner_id
         WHERE u.username = 'bob' ORDER BY t.id LIMIT 1`,
      );
      const res = await request(app)
        .get(`/api/transactions/${listed.rows[0].id}`)
        .set('Authorization', auth(bob));
      expect(res.status).toBe(200);
      expect(res.body.transaction.id).toBe(listed.rows[0].id);
    });

    it("forbids reading another user's transaction", async () => {
      const listed = await pool.query(
        `SELECT t.id FROM transactions t JOIN users u ON u.id = t.owner_id
         WHERE u.username = 'alice' ORDER BY t.id LIMIT 1`,
      );
      const res = await request(app)
        .get(`/api/transactions/${listed.rows[0].id}`)
        .set('Authorization', auth(bob));
      expect(res.status).toBe(404);
    });""",
    ),
)

# ----------------------------------------------------------------- upload -----
fix(
    "VULN-016",
    (
        "src/routes/upload.ts",
        """  const storedName = decodeURIComponent(file.originalname);
  const target = path.join(UPLOAD_DIR, storedName);""",
        """  // VULN-016 fix: reduce the name to a single path segment, then verify the
  // resolved target is still inside the upload root before writing.
  const storedName = path.basename(decodeURIComponent(file.originalname));
  const target = path.join(UPLOAD_DIR, storedName);
  const resolvedRoot = path.resolve(UPLOAD_DIR);
  if (!path.resolve(target).startsWith(resolvedRoot + path.sep)) {
    res.status(400).json({ error: 'invalid_filename' });
    return;
  }""",
    ),
)

fix(
    "VULN-017",
    (
        "src/routes/upload.ts",
        """const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
});""",
        """// VULN-017 fix: only document and image types are accepted.
const ALLOWED_EXTENSIONS = new Set(['.txt', '.pdf', '.csv', '.png', '.jpg', '.jpeg']);
const ALLOWED_MIME = new Set([
  'text/plain',
  'application/pdf',
  'text/csv',
  'image/png',
  'image/jpeg',
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(path.basename(file.originalname)).toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext) || !ALLOWED_MIME.has(file.mimetype)) {
      cb(new Error('file_type_not_allowed'));
      return;
    }
    cb(null, true);
  },
});""",
    ),
)

# ------------------------------------------------------------------ fetch -----
fix(
    "VULN-018",
    (
        "src/routes/fetch.ts",
        """  try {
    const upstream = await fetch(url, { timeout: 8000 });""",
        """  // VULN-018 fix: only allowlisted public hosts may be fetched.
  if (!isAllowedUrl(url)) {
    res.status(400).json({ error: 'url_not_allowed' });
    return;
  }

  try {
    const upstream = await fetch(url, { timeout: 8000 });""",
    ),
    (
        "src/routes/fetch.ts",
        "const router = Router();",
        """const router = Router();

// VULN-018/019 fix: allowlist of public hosts. Loopback, link-local, private and
// metadata addresses are refused, and only http/https may be used.
const ALLOWED_HOSTS = new Set(['api.vulnbank.test', 'status.vulnbank.test']);

function isAllowedUrl(raw: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
  if (!ALLOWED_HOSTS.has(parsed.hostname)) return false;
  return true;
}""",
    ),
    (
        "tests/fetch.test.ts",
        """  it('proxies a reachable URL and returns the body', async () => {
    const res = await request(app).post('/api/fetch').set('Authorization', auth(token)).send({ url: upstreamUrl });
    expect(res.status).toBe(200);
    expect(res.body.status).toBe(200);
    expect(res.body.body).toBe('upstream-ok');
  });""",
        """  it('refuses a host that is not on the allowlist', async () => {
    const res = await request(app).post('/api/fetch').set('Authorization', auth(token)).send({ url: upstreamUrl });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('url_not_allowed');
  });""",
    ),
    (
        "tests/fetch.test.ts",
        """  it('reports an upstream failure as 502', async () => {
    const res = await request(app)
      .post('/api/fetch')
      .set('Authorization', auth(token))
      .send({ url: 'http://127.0.0.1:1/nope' });
    expect(res.status).toBe(502);
    expect(res.body.error).toBe('upstream_failed');
  });""",
        """  it('refuses a loopback address', async () => {
    const res = await request(app)
      .post('/api/fetch')
      .set('Authorization', auth(token))
      .send({ url: 'http://127.0.0.1:1/nope' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('url_not_allowed');
  });""",
    ),
)

fix(
    "VULN-019",
    (
        "src/routes/fetch.ts",
        "  const url = typeof body.url === 'string' ? body.url : '';",
        """  const url = typeof body.url === 'string' ? body.url : '';

  // VULN-019 fix: metadata and link-local addresses are refused before any
  // request leaves the process.
  if (/^https?:\\/\\/(169\\.254\\.|127\\.|localhost|\\[::1\\]|metadata\\.)/i.test(url)) {
    res.status(400).json({ error: 'url_not_allowed' });
    return;
  }""",
    ),
    (
        "tests/fetch.test.ts",
        """  it('proxies a reachable URL and returns the body', async () => {
    const res = await request(app).post('/api/fetch').set('Authorization', auth(token)).send({ url: upstreamUrl });
    expect(res.status).toBe(200);
    expect(res.body.status).toBe(200);
    expect(res.body.body).toBe('upstream-ok');
  });""",
        """  it('refuses a loopback address that is not allowlisted', async () => {
    const res = await request(app).post('/api/fetch').set('Authorization', auth(token)).send({ url: upstreamUrl });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('url_not_allowed');
  });""",
    ),
    (
        "tests/fetch.test.ts",
        """  it('reports an upstream failure as 502', async () => {
    const res = await request(app)
      .post('/api/fetch')
      .set('Authorization', auth(token))
      .send({ url: 'http://127.0.0.1:1/nope' });
    expect(res.status).toBe(502);
    expect(res.body.error).toBe('upstream_failed');
  });""",
        """  it('refuses a loopback address', async () => {
    const res = await request(app)
      .post('/api/fetch')
      .set('Authorization', auth(token))
      .send({ url: 'http://127.0.0.1:1/nope' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('url_not_allowed');
  });""",
    ),

)
fix(
    "VULN-020",
    (
        "src/routes/redirect.ts",
        "  res.redirect(302, to);",
        """  // VULN-020 fix: only same-site relative paths and allowlisted hosts may be
  // redirected to.
  const ALLOWED_HOSTS = new Set(['vulnbank.test', 'www.vulnbank.test']);
  let target: URL | null = null;
  try {
    target = new URL(to, 'https://vulnbank.test');
  } catch {
    target = null;
  }
  if (!target || !ALLOWED_HOSTS.has(target.hostname)) {
    res.status(400).json({ error: 'redirect_not_allowed' });
    return;
  }
  res.redirect(302, target.toString());""",
    ),
    (
        "tests/fetch.test.ts",
        """  it('issues a 302 to the requested target', async () => {
    const res = await request(app).get('/api/redirect?to=/health');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/health');
  });""",
        """  it('issues a 302 to a same-site target', async () => {
    const res = await request(app).get('/api/redirect?to=/health');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('https://vulnbank.test/health');
  });

  it('refuses an external redirect target', async () => {
    const res = await request(app).get('/api/redirect?to=https://evil.example.test/x');
    expect(res.status).toBe(400);
  });""",
    ),
)

# --------------------------------------------------------------- comments -----
fix(
    "VULN-021",
    (
        "src/routes/comments.ts",
        """    const items = result.rows
      .map((c) => `<li><b>${c.author}</b>: ${c.body}</li>`)
      .join('');""",
        """    const items = result.rows
      .map((c) => `<li><b>${escapeHtml(c.author)}</b>: ${escapeHtml(c.body)}</li>`)
      .join('');""",
    ),
    (
        "src/routes/comments.ts",
        "const router = Router();",
        """const router = Router();

// VULN-021 fix: comment content is encoded when it is rendered.
function escapeHtml(value: string): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}""",
    ),
)

fix(
    "VULN-022",
    (
        "src/app.ts",
        "  app.use(express.json({ limit: '2mb' }));",
        """  // VULN-022 fix: a restrictive Content-Security-Policy on every response.
  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    );
    next();
  });

  app.use(express.json({ limit: '2mb' }));""",
    ),
)

# ----------------------------------------------------------------- admin ------
fix(
    "VULN-023",
    (
        "src/routes/admin.ts",
        """  exec(`psql "$DATABASE_URL" -t -c "${cmd}"`, { timeout: 5000 }, (err, stdout, stderr) => {""",
        """  // VULN-023 fix: the SQL is passed to psql through argv and stdin rather than
  // being interpolated into a shell string, so shell metacharacters are inert.
  execFile(
    'psql',
    [String(process.env.DATABASE_URL || ''), '-t', '-c', cmd],
    { timeout: 5000 },
    (err, stdout, stderr) => {""",
    ),
    (
        "src/routes/admin.ts",
        """    res.status(200).json({ stdout: stdout.trim(), stderr: stderr.trim() });
  });""",
        """      res.status(200).json({ stdout: stdout.trim(), stderr: stderr.trim() });
    },
  );""",
    ),
    (
        "src/routes/admin.ts",
        """      res.status(500).json({ error: 'exec_failed', detail: err.message, stderr });
      return;
    }""",
        """        res.status(500).json({ error: 'exec_failed', detail: err.message, stderr });
        return;
      }""",
    ),
    (
        "src/routes/admin.ts",
        "import { exec } from 'child_process';",
        "import { execFile } from 'child_process';",
    ),
)

# ---------------------------------------------------------------- export ------
fix(
    "VULN-024",
    (
        "src/routes/export.ts",
        """      lines.push([r.id, r.owner_id, r.username, r.kind, r.counterparty, r.amount, r.note].join(','));""",
        """      lines.push(
        [r.id, r.owner_id, r.username, r.kind, r.counterparty, r.amount, r.note]
          .map(csvCell)
          .join(','),
      );""",
    ),
    (
        "src/routes/export.ts",
        "const router = Router();",
        """const router = Router();

// VULN-024 fix: quote every cell and neutralise the leading characters that a
// spreadsheet would interpret as a formula.
function csvCell(value: unknown): string {
  const text = String(value ?? '');
  const safe = /^[=+@]/.test(text) ? `'${text}` : text;
  return `"${safe.replace(/"/g, '""')}"`;
}""",
    ),
    (
        "tests/export.test.ts",
        "    expect(lines[1].split(',').length).toBe(7);",
        "    expect(lines[1].startsWith('\"1\",')).toBe(true);",
    ),
)

# ---------------------------------------------------------------- webhook -----
fix(
    "VULN-025",
    (
        "src/routes/webhook.ts",
        """  const event = (req.body || {}) as StripeEvent;
  const type = typeof event.type === 'string' ? event.type : '';""",
        """  // VULN-025 fix: the payload is HMAC-verified against the Stripe signing secret
  // before any of it is trusted.
  const signatureHeader = req.headers['stripe-signature'];
  const rawBody = JSON.stringify(req.body || {});
  if (typeof signatureHeader !== 'string' || !verifyStripeSignature(signatureHeader, rawBody)) {
    res.status(400).json({ error: 'invalid_signature' });
    return;
  }

  const event = (req.body || {}) as StripeEvent;
  const type = typeof event.type === 'string' ? event.type : '';""",
    ),
    (
        "src/routes/webhook.ts",
        """import { Router, Request, Response } from 'express';
import pool from '../db';""",
        """import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import pool from '../db';

const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

// Stripe sends `t=<timestamp>,v1=<hex hmac>`; recompute and compare in constant time.
function verifyStripeSignature(header: string, payload: string): boolean {
  if (!STRIPE_WEBHOOK_SECRET) return false;
  const parts = Object.fromEntries(
    header.split(',').map((p) => p.split('=') as [string, string]),
  );
  const timestamp = parts.t;
  const expected = parts.v1;
  if (!timestamp || !expected) return false;
  const computed = crypto
    .createHmac('sha256', STRIPE_WEBHOOK_SECRET)
    .update(`${timestamp}.${payload}`)
    .digest('hex');
  if (computed.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(expected));
}""",
    ),
    (
        "tests/webhook.test.ts",
        """import request from 'supertest';
import { app, resetDatabase, balanceOf } from './helpers';""",
        """import request from 'supertest';
import crypto from 'crypto';
import { app, resetDatabase, balanceOf } from './helpers';

const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

function signedHeaders(body: unknown): Record<string, string> {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify(body);
  const signature = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(`${timestamp}.${payload}`)
    .digest('hex');
  return { 'Stripe-Signature': `t=${timestamp},v1=${signature}` };
}""",
    ),
    (
        "tests/webhook.test.ts",
        """    const res = await request(app)
      .post('/api/webhook/stripe')
      .send({ type: 'charge.succeeded', data: { object: { customer: 'bob', amount: 12345 } } });""",
        """    const event = { type: 'charge.succeeded', data: { object: { customer: 'bob', amount: 12345 } } };
    const res = await request(app).post('/api/webhook/stripe').set(signedHeaders(event)).send(event);""",
    ),
    (
        "tests/webhook.test.ts",
        """    const res = await request(app).post('/api/webhook/stripe').send({ type: 'invoice.paid' });""",
        """    const event = { type: 'invoice.paid' };
    const res = await request(app).post('/api/webhook/stripe').set(signedHeaders(event)).send(event);""",
    ),
    (
        "tests/webhook.test.ts",
        """    const res = await request(app).post('/api/webhook/stripe').send({});""",
        """    const event = {};
    const res = await request(app).post('/api/webhook/stripe').set(signedHeaders(event)).send(event);""",
    ),
    (
        "tests/webhook.test.ts",
        """    const res = await request(app)
      .post('/api/webhook/stripe')
      .send({ type: 'charge.succeeded', data: { object: { customer: 'ghost', amount: 100 } } });""",
        """    const event = { type: 'charge.succeeded', data: { object: { customer: 'ghost', amount: 100 } } };
    const res = await request(app).post('/api/webhook/stripe').set(signedHeaders(event)).send(event);""",
    ),
    (
        "tests/webhook.test.ts",
        """  it('404s when the customer does not exist', async () => {""",
        """  it('rejects an event with no valid signature', async () => {
    const res = await request(app).post('/api/webhook/stripe').send({ type: 'invoice.paid' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_signature');
  });

  it('404s when the customer does not exist', async () => {""",
    ),
)

# ----------------------------------------------------------------- config -----
fix(
    "VULN-026",
    (
        "src/routes/config.ts",
        """  const env = { ...process.env };
  const extra = {
    jwt_secret: 'vulnbank-dev-secret-do-not-ship',
    stripe_secret_key: 'sk_test_51H8vulnbankFakeKeyDoNotUse',
    db_password: 'Sup3rS3cretBankPwd!',
  };
  res.status(200).json({ config: env, secrets: extra, version: '1.0.0' });""",
        """  // VULN-026 fix: only non-sensitive runtime settings are exposed.
  res.status(200).json({
    config: {
      port: Number(process.env.PORT || 4000),
      upload_dir: process.env.UPLOAD_DIR || './uploads',
    },
    version: '1.0.0',
  });""",
    ),
)

fix(
    "VULN-028",
    (
        "src/db.ts",
        "  password: 'Sup3rS3cretBankPwd!', // line 7 — hardcoded_db_password",
        "  password: process.env.DB_PASSWORD || '', // VULN-028 fix: credential comes from the environment",
    ),
)

# ------------------------------------------------------------------- hash -----
fix(
    "VULN-029",
    (
        "src/auth/hash.ts",
        """import crypto from 'crypto';

// VULN-029: passwords are hashed with MD5 (CWE-327). MD5 is fast and
// collision-broken, so offline cracking of a leaked hash table is trivial.
export function hashPassword(plain: string): string {
  return crypto.createHash('md5').update(plain).digest('hex');
}

export function verifyPassword(plain: string, stored: string): boolean {
  return hashPassword(plain) === stored;
}""",
        """import bcrypt from 'bcryptjs';

// VULN-029 fix: passwords are hashed with bcrypt, a salted adaptive-cost
// function, instead of unsalted MD5.
const BCRYPT_ROUNDS = 10;

export function hashPassword(plain: string): string {
  return bcrypt.hashSync(plain, BCRYPT_ROUNDS);
}

export function verifyPassword(plain: string, stored: string): boolean {
  if (!stored) return false;
  try {
    return bcrypt.compareSync(plain, stored);
  } catch {
    return false;
  }
}""",
    ),
)

# --------------------------------------------------------------- settings -----
fix(
    "VULN-030",
    (
        "src/routes/settings.ts",
        """function merge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  for (const key of Object.keys(source)) {""",
        """const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function merge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  for (const key of Object.keys(source)) {
    // VULN-030 fix: never write through keys that reach the prototype chain.
    if (UNSAFE_KEYS.has(key)) continue;""",
    ),
)

# ----------------------------------------------------------------- import -----
fix(
    "VULN-031",
    (
        "src/routes/import.ts",
        """    const payload = typeof body.batch === 'string' ? body.batch : JSON.stringify(body.batch);
    const restored = serialize.unserialize(payload);""",
        """    // VULN-031 fix: batches are parsed as plain JSON. node-serialize evaluates the
    // function wrappers it emits, which is remote code execution.
    const payload = typeof body.batch === 'string' ? body.batch : JSON.stringify(body.batch);
    if (typeof body.batch === 'string' && payload.includes('_$$ND_FUNC$$_')) {
      res.status(400).json({ error: 'unsafe_payload' });
      return;
    }
    const restored = JSON.parse(payload);""",
    ),
    (
        "src/routes/import.ts",
        "import serialize from 'node-serialize';\n",
        "",
    ),
)

# -------------------------------------------------------------------- app -----
fix(
    "VULN-032",
    (
        "src/app.ts",
        """    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');""",
        """    // VULN-032 fix: the origin is echoed only for allowlisted callers, and
    // credentials are never combined with a wildcard.
    const ALLOWED_ORIGINS = new Set([
      'https://vulnbank.test',
      'https://app.vulnbank.test',
    ]);
    const origin = req.headers.origin;
    if (typeof origin === 'string' && ALLOWED_ORIGINS.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Vary', 'Origin');
    }""",
    ),
    (
        "tests/app.test.ts",
        """    expect(res.headers['access-control-allow-methods']).toContain('POST');""",
        """    expect(res.headers['access-control-allow-methods']).toContain('POST');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();""",
    ),
)


def normalise_diff(text: str, work: str) -> str:
    """Rewrite git's headers so every path is a/src/... or b/src/...

    `git diff --no-index` mixes a relative a/ path with an absolute b/ path, and
    `patch -p1` needs both sides to strip to the same tree-relative path.
    """
    out: list[str] = []
    for line in text.splitlines():
        if line.startswith("+++ "):
            rest = line[4:].split("\t")[0]
            for prefix in ("b/", ""):
                if rest.startswith(prefix) and work in rest:
                    rest = rest[rest.index(work) + len(work):].lstrip("/")
                    break
            line = f"+++ b/{rest}"
        elif line.startswith("--- "):
            rest = line[4:].split("\t")[0]
            if rest.startswith("a/"):
                rest = rest[2:]
            line = f"--- a/{rest}"
        elif line.startswith("diff --git "):
            parts = line.split(" ")
            left = parts[2][2:] if parts[2].startswith("a/") else parts[2]
            right = parts[3]
            if work in right:
                right = right[right.index(work) + len(work):].lstrip("/")
            line = f"diff --git a/{left} b/{right}"
        out.append(line)
    return "\n".join(out) + "\n"


def apply_edits(edits: list[tuple[str, str, str]], target_root: str) -> list[str]:
    touched: list[str] = []
    for rel, old, new in edits:
        if old == new:
            continue
        path = os.path.join(target_root, rel)
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        if old not in text:
            raise SystemExit(f"anchor missing in {rel}:\n---\n{old[:300]}\n---")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text.replace(old, new, 1))
        if rel not in touched:
            touched.append(rel)
    return touched


def main() -> None:
    pristine = tempfile.mkdtemp(prefix="vulnbank-pristine-")
    work = tempfile.mkdtemp(prefix="vulnbank-work-")
    try:
        for root in (pristine, work):
            for sub in ("src", "tests"):
                shutil.copytree(os.path.join(ROOT, sub), os.path.join(root, sub))

        os.makedirs(os.path.join(ROOT, "patches"), exist_ok=True)
        for vuln_id in sorted(FIXES):
            # reset the working copy
            for sub in ("src", "tests"):
                shutil.rmtree(os.path.join(work, sub))
                shutil.copytree(os.path.join(pristine, sub), os.path.join(work, sub))

            touched = apply_edits(FIXES[vuln_id], work)
            if not touched:
                print(f"SKIP  {vuln_id}  (no effective edits)")
                continue

            # Run from inside the pristine copy with a relative path so git emits
            # a/src/... and b/src/... headers that `patch -p1` can resolve.
            diff = subprocess.run(
                ["git", "diff", "--no-index", "--relative", "--src-prefix=a/", "--dst-prefix=b/", ".", work],
                capture_output=True,
                text=True,
                cwd=pristine,
            )
            # git diff --no-index exits 1 when files differ; that is success here.
            if diff.returncode not in (0, 1):
                raise SystemExit(f"git diff failed for {vuln_id}: {diff.stderr}")

            patch_text = normalise_diff(diff.stdout, work)
            patch_path = os.path.join(ROOT, "patches", f"{vuln_id}.diff")
            with open(patch_path, "w", encoding="utf-8") as handle:
                handle.write(patch_text)
            print(f"WROTE {vuln_id}.diff  ({len(patch_text.splitlines())} lines, files: {', '.join(touched)})")
    finally:
        shutil.rmtree(pristine, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
