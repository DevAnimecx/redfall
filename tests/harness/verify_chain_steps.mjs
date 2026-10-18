// Exercises the multi-step chain runner against live HTTP servers on this host.
//
// A chain verdict decides whether an exploit path is real, so the code that
// produces it must be verifiable without a container. This starts two real
// servers, stiches their responses into each other through the same
// substitution/extraction code the sandbox harness uses, and checks that every
// failure mode lands on the right step.

import { createServer } from 'node:http';
import { createConnection } from 'node:net';
import crypto from 'node:crypto';

import {
  bindings,
  chainExpectExpr,
  evaluate,
  extractValues,
  jwtHs256,
  parseHttpResponse,
  pathMatches,
  pickValue,
  placeholders,
  prepareStepRequest,
  runStepChain,
  splitRawRequest,
  substitute,
} from '../../src/redfall/validation/harness_internals.mjs';

let failures = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) failures += 1;
  console.log(`   ${ok ? 'OK ' : 'BAD'} ${label}${ok ? '' : `\n        got  ${JSON.stringify(got)}\n        want ${JSON.stringify(want)}`}`);
};
const checkTruthy = (label, got) => {
  const ok = Boolean(got);
  if (!ok) failures += 1;
  console.log(`   ${ok ? 'OK ' : 'BAD'} ${label}${ok ? '' : ` (got ${JSON.stringify(got)})`}`);
};

const PORT = 4231;
const SIGNING_KEY = 'sk-signing-9911';

// ---------------------------------------------------------------- servers
// Server A behaves like the vulnerable application under test.
const app = createServer((req, res) => {
  let body = '';
  req.on('data', (d) => (body += d));
  req.on('end', () => {
    const send = (status, payload) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    };
    if (req.url === '/api/login') {
      const creds = JSON.parse(body || '{}');
      if (creds.username === 'alice' && creds.password === 'Alice!Passw0rd') {
        return send(200, { token: 'tok-alice', role: 'user' });
      }
      return send(401, { error: 'invalid credentials' });
    }
    if (req.url === '/api/debug/keys') {
      if (req.headers.authorization !== 'Bearer tok-alice') return send(403, { error: 'forbidden' });
      return send(200, { keys: [{ id: 'k1', secret: 'not-the-one' }, { id: 'k2', secret: SIGNING_KEY }] });
    }
    if (req.url === '/api/admin/flag') {
      const header = String(req.headers.authorization || '');
      const token = header.startsWith('Bearer ') ? header.slice(7) : '';
      const parts = token.split('.');
      if (parts.length !== 3) return send(403, { error: 'malformed token' });
      const expected = crypto
        .createHmac('sha256', SIGNING_KEY)
        .update(`${parts[0]}.${parts[1]}`)
        .digest('base64url');
      if (expected !== parts[2]) return send(403, { error: 'bad signature' });
      const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      if (claims.role !== 'admin') return send(403, { error: 'not admin' });
      return send(200, { flag: 'REDFALL_CHAIN_OK' });
    }
    if (req.url === '/api/seed') {
      return send(200, { seeded: true });
    }
    return send(404, { error: 'not found' });
  });
});

await new Promise((r) => app.listen(PORT, '127.0.0.1', r));

// ------------------------------------------------------------- real send
function realSend(raw) {
  const req = prepareStepRequest(raw);
  return new Promise((resolve, reject) => {
    const conn = createConnection({ host: '127.0.0.1', port: PORT }, () => {
      const lines = [`${req.method} ${req.path} HTTP/1.1`, `Host: 127.0.0.1:${PORT}`, 'Connection: close'];
      for (const [k, v] of Object.entries(req.headers)) lines.push(`${k}: ${v}`);
      conn.write(`${lines.join('\r\n')}\r\n\r\n${req.body}`);
    });
    conn.setTimeout(10_000, () => conn.destroy(new Error('timed out')));
    conn.on('error', reject);
    let raw = '';
    conn.on('data', (d) => (raw += d.toString('binary')));
    conn.on('close', () => {
      const sep = raw.indexOf('\r\n\r\n');
      const head = sep === -1 ? raw : raw.slice(0, sep);
      const bodyBuf = Buffer.from(sep === -1 ? '' : raw.slice(sep + 4), 'binary');
      resolve(parseHttpResponse(head, bodyBuf));
    });
  });
}

// --------------------------------------------------- pure helper checks
console.log('-- substitute / placeholders');
check('substitutes a produced value', substitute('Bearer {{TOKEN}}', { TOKEN: 'abc' }), 'Bearer abc');
check('lists the names it needs', placeholders('a={{A}} b={{B}} {{A}}'), ['A', 'B', 'A']);
let threw = false;
try {
  substitute('{{NOPE}}', {});
} catch (err) {
  threw = /no earlier step produced/.test(err.message);
}
check('unbound placeholder throws', threw, true);

console.log('-- pathMatches / pickValue');
const leaked = { results: [{ email: 'alice@bank.test' }, { email: '$2a$bcrypt' }] };
check('wildcard path collects every row', pathMatches(leaked, 'results[*].email'), ['alice@bank.test', '$2a$bcrypt']);
check('indexed path picks one row', pathMatches(leaked, 'results[1].email'), ['$2a$bcrypt']);
check('missing path yields nothing', pathMatches(leaked, 'nope.deep'), []);
check(
  'first_starts_with selects the hash-shaped value',
  pickValue(pathMatches(leaked, 'results[*].email'), { pick: 'first_starts_with', starts_with: '$2a$' }),
  '$2a$bcrypt',
);

console.log('-- jwt_hs256');
const minted = jwtHs256(SIGNING_KEY, { sub: 1, role: 'admin' });
const [h, p, sig] = minted.split('.');
const recomputed = crypto.createHmac('sha256', SIGNING_KEY).update(`${h}.${p}`).digest('base64url');
check('the token is signed off-box with the stolen key', sig, recomputed);
check('the claims survive', JSON.parse(Buffer.from(p, 'base64url').toString()).role, 'admin');

console.log('-- splitRawRequest');
const multipart = splitRawRequest(
  'POST /upload HTTP/1.1\nContent-Type: multipart/form-data; boundary=X\n\n--X\nname=file\n--X--\n',
);
checkTruthy('multipart body is rebuilt with CRLF', multipart.body.includes('--X\r\nname=file\r\n--X--\r\n'));
const clrfed = 'POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=X\r\n\r\n--X\r\nname=file\r\n--X--\r\n';
check('an already-CRLF multipart body is untouched', splitRawRequest(clrfed).body, '--X\r\nname=file\r\n--X--\r\n');
const prepared = prepareStepRequest(
  'POST /api/login HTTP/1.1\nContent-Type: application/json\nContent-Length: 999\n\n{"a":1}',
);
check('a declared Content-Length is replaced by the real one', prepared.headers['Content-Length'], '7');

// ------------------------------------------------------ the chain itself
console.log('-- a three-step chain over live HTTP');
function loginStep(overrides = {}) {
  return {
    id: 'F-1',
    request:
      `POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:${PORT}\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n` +
      '{"username":"alice","password":"Alice!Passw0rd"}',
    expect_expr: 'status === 200 && json.token !== undefined',
    extract: { AUTH_TOKEN: { from: 'json', path: 'token' } },
    ...overrides,
  };
}
function keysStep(overrides = {}) {
  return {
    id: 'F-2',
    request:
      `GET /api/debug/keys HTTP/1.1\r\nHost: 127.0.0.1:${PORT}\r\n` +
      'Authorization: Bearer {{AUTH_TOKEN}}\r\n\r\n',
    expect_expr: 'status === 200 && Array.isArray(json.keys)',
    extract: {
      SIGNING_KEY: { from: 'json', path: 'keys[*].secret', pick: 'first_starts_with', starts_with: 'sk-' },
      FORGED: { from: 'jwt_hs256', secret: '{{SIGNING_KEY}}', claims: { sub: 1, role: 'admin' } },
    },
    ...overrides,
  };
}
function flagStep(overrides = {}) {
  return {
    id: 'F-3',
    request:
      `GET /api/admin/flag HTTP/1.1\r\nHost: 127.0.0.1:${PORT}\r\n` +
      'Authorization: Bearer {{FORGED}}\r\n\r\n',
    expect_expr: "status === 200 && json.flag === 'REDFALL_CHAIN_OK'",
    ...overrides,
  };
}

const happy = await runStepChain([loginStep(), keysStep(), flagStep()], {
  send: realSend,
  extra: { expectExpr: chainExpectExpr(3) },
});
check('the chain reproduces', happy.ok, true);
check('every step is recorded', happy.steps.map((s) => s.n), [1, 2, 3]);
check('the extracted auth token is the real one', happy.values.AUTH_TOKEN, 'tok-alice');
check('the signing key came out of the second response', happy.values.SIGNING_KEY, SIGNING_KEY);
check('the forged token is a JWT', happy.values.FORGED.split('.').length, 3);
check('nothing failed', happy.failure, null);
checkTruthy('evidence names each step', happy.evidence.join('\n').includes('step 3 F-3 -> 200'));

// The token the application accepted in step 3 must be signed with the key that
// was stolen in step 2, not with a value the test supplied.
const forgedClaims = JSON.parse(Buffer.from(happy.values.FORGED.split('.')[1], 'base64url').toString());
const forgedSig = crypto
  .createHmac('sha256', happy.values.SIGNING_KEY)
  .update(happy.values.FORGED.split('.').slice(0, 2).join('.'))
  .digest('base64url');
check('step 3 accepted a token signed with the stolen key', happy.values.FORGED.split('.')[2], forgedSig);
check('the forged claims say admin', forgedClaims.role, 'admin');

console.log('-- a step that fails stops the chain at that step');
const broken = await runStepChain([loginStep(), keysStep({ request: keysStep().request.replace('{{AUTH_TOKEN}}', 'wrong-token') }), flagStep()], {
  send: realSend,
  extra: { expectExpr: chainExpectExpr(3) },
});
check('the chain does not reproduce', broken.ok, false);
check('the failure points at step 2', broken.failure.step, 1);
check('the failure kind is a predicate miss', broken.failure.kind, 'predicate');
check('only step 1 is credited', broken.stepsPassed, 1);

console.log('-- a step that needs a value nobody produced');
const unbound = await runStepChain([loginStep(), keysStep({ request: 'GET /api/x HTTP/1.1\r\nHost: h\r\nX-T: {{MISSING}}\r\n\r\n' })], {
  send: realSend,
  extra: { expectExpr: chainExpectExpr(2) },
});
check('the chain refuses to run the unbound step', unbound.failure.kind, 'unbound');
check('the failure points at step 2', unbound.failure.step, 1);
check('only step 1 is credited', unbound.stepsPassed, 1);

console.log('-- an extraction that produces nothing');
const emptyExtract = await runStepChain(
  [loginStep(), keysStep({ extract: { NOTHING: { from: 'json', path: 'nope[*].deep' } } })],
  { send: realSend, extra: { expectExpr: chainExpectExpr(2) } },
);
check('the chain stops on the empty extraction', emptyExtract.failure.kind, 'extract');
check('the step itself had held', emptyExtract.stepsPassed, 2);
checkTruthy('the reason names the value', emptyExtract.failure.message.includes('NOTHING'));

console.log('-- setup and followup hooks');
const withHooks = await runStepChain(
  [loginStep({ setup: { request: `POST /api/seed HTTP/1.1\r\nHost: 127.0.0.1:${PORT}\r\nContent-Length: 0\r\n\r\n`, expect_expr: 'status === 200' } })],
  {
    send: realSend,
    extra: { expectExpr: chainExpectExpr(1) },
    hooks: {
      before: async (step, index, ctx) => {
        const res = await realSend(ctx.substitute(step.setup.request));
        const ok = evaluate(step.setup.expect_expr, bindings(res, { setup_status: res.status })) === true;
        return { ok, res, evidence: `step ${index + 1} setup -> ${res.status}` };
      },
    },
  },
);
check('a chain with a satisfied setup runs', withHooks.ok, true);
checkTruthy('the setup ran before the step', withHooks.evidence.some((line) => line.includes('setup -> 200')));

const failedSetup = await runStepChain([loginStep()], {
  send: realSend,
  extra: { expectExpr: chainExpectExpr(1) },
  hooks: {
    before: async () => ({ ok: false, res: { status: 500 }, message: 'the seed row was not created' }),
  },
});
check('a failed setup fails the chain', failedSetup.ok, false);
check('the failure kind is setup', failedSetup.failure.kind, 'setup');
check('no step is credited', failedSetup.stepsPassed, 0);
checkTruthy('the setup message is carried through', failedSetup.failure.message.includes('seed row'));

console.log('-- extractValues refuses an unbound selector');
threw = false;
try {
  extractValues({ X: { from: 'jwt_hs256', secret: '{{NEVER_SET}}' } }, { status: 200, body: '', json: null, headers: {} }, {});
} catch (err) {
  threw = /no earlier step produced/.test(err.message);
}
check('an unbound derive is refused', threw, true);

app.close();
console.log(failures === 0 ? '\nALL CHAIN HARNESS CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
