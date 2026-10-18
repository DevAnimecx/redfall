// Exercises the harness's real request/response/predicate code path against a
// live Node HTTP server on this host. This verifies the code that decides
// whether an exploit worked; it does not replace the gVisor execution, which
// this sandbox cannot provide.

import { createServer } from 'node:http';
import { createConnection } from 'node:net';
import { readFileSync } from 'node:fs';

import { bindings, csvFields, dechunk, evaluate, parseHttpResponse, parseRawRequest } from '../../src/redfall/validation/harness_internals.mjs';

let failures = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) failures += 1;
  console.log(`   ${ok ? 'OK ' : 'BAD'} ${label}${ok ? '' : `\n        got  ${JSON.stringify(got)}\n        want ${JSON.stringify(want)}`}`);
};

// ---- 1. raw request parsing, including CRLF -----------------------------
console.log('-- parseRawRequest');
const parsed = parseRawRequest(
  'POST /api/auth/login HTTP/1.1\r\nHost: localhost:4000\r\nContent-Type: application/json\r\n\r\n{"a":1}\r\n',
);
// parseRawRequest normalises CRLF to LF first, so the body keeps the LF form.
check('method', parsed.method, 'POST');
check('path', parsed.path, '/api/auth/login');
check('content-type', parsed.headers['content-type'], 'application/json');
check('body normalised to LF', parsed.body, '{"a":1}\n');
check('CRLF did not leak into a header value', parsed.headers.host, 'localhost:4000');

const parsedLf = parseRawRequest('GET /x HTTP/1.1\nHost: h\n\n');
check('LF-only body is empty', parsedLf.body, '');
check('LF-only path', parsedLf.path, '/x');

// ---- 2. csvFields -------------------------------------------------------
console.log('-- csvFields');
check('simple', csvFields('a,b,c\n1,2,3'), ['a', 'b', 'c', '1', '2', '3']);
check('quoted comma', csvFields('id,"=cmd|calc",3'), ['id', '=cmd|calc', '3']);
check('empty body', csvFields(''), []);

// ---- 2b. chunked transfer encoding --------------------------------------
console.log('-- dechunk');
// Build the frame from the payload so the hex sizes cannot drift out of sync.
const frame = (...chunks) =>
  Buffer.from(chunks.map((c) => `${c.length.toString(16)}\r\n${c}\r\n`).join('') + '0\r\n\r\n', 'binary');
const payload = '{"token":"t","user":{"role":"admin"}}';
check('chunk prefixes removed', dechunk(frame(payload)).toString('utf8'), payload);
check(
  'multi-chunk body reassembled in order',
  dechunk(frame('{"a":"', 'one","b":', '"two"}')).toString('utf8'),
  '{"a":"one","b":"two"}',
);
check('terminator stops parsing', dechunk(frame('abc') .subarray(0, 9).length ? Buffer.from('3\r\nabc\r\n0\r\ntrailing', 'binary') : null).toString('utf8'), 'abc');

// ---- 3. response parsing ------------------------------------------------
console.log('-- parseHttpResponse');
const head = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Trace: abc\r\n';
const res = parseHttpResponse(head, Buffer.from('{"token":"t","user":{"role":"admin"}}'));
check('status', res.status, 200);
check('header lowercased', res.headers['x-trace'], 'abc');
check('json parsed', res.json.user.role, 'admin');
const notJson = parseHttpResponse('HTTP/1.1 404 Not Found\r\n', Buffer.from('nope'));
check('non-JSON -> json null', notJson.json, null);
check('non-JSON status', notJson.status, 404);

// ---- 4. the real VULN-001 predicate -------------------------------------
console.log('-- real manifest predicate evaluated against a real HTTP exchange');
// The ground-truth PoC for VULN-001, exported verbatim from the range manifest.
// The PoC is passed in as a JSON file so this test never depends on a committed
// fixture; tests/test_harness_predicate.py extracts it from the range manifest.
const pocArg = process.argv.indexOf('--poc');
if (pocArg === -1 || !process.argv[pocArg + 1]) {
  console.error('usage: verify_harness.mjs --poc <path-to-poc.json>');
  process.exit(2);
}
const poc = JSON.parse(readFileSync(process.argv[pocArg + 1], 'utf8'));
const expr = poc.expect_expr;
const rawReq = poc.request;
console.log(`   expect_expr: ${expr}`);

// A server that behaves like the vulnerable login handler for this payload.
const server = createServer((req, res2) => {
  let body = '';
  req.on('data', (d) => (body += d));
  req.on('end', () => {
    const injected = body.includes('UNION SELECT');
    if (req.url === '/api/auth/login' && injected) {
      res2.writeHead(200, { 'Content-Type': 'application/json' });
      res2.end(JSON.stringify({ token: 'eyJhbGciOiJIUzI1NiJ9.fake', user: { id: 1, username: 'admin', role: 'admin' } }));
    } else {
      res2.writeHead(401, { 'Content-Type': 'application/json' });
      res2.end(JSON.stringify({ error: 'Invalid credentials' }));
    }
  });
});

await new Promise((r) => server.listen(4111, '127.0.0.1', r));

function rawHttp(reqParsed) {
  return new Promise((resolve, reject) => {
    const conn = createConnection({ host: '127.0.0.1', port: 4111 }, () => {
      const lines = [`${reqParsed.method} ${reqParsed.path} HTTP/1.1`, 'Host: 127.0.0.1:4111', 'Connection: close'];
      for (const [k, v] of Object.entries(reqParsed.headers)) {
        if (k === 'host' || k === 'connection') continue;
        lines.push(`${k}: ${v}`);
      }
      lines.push(`Content-Length: ${Buffer.byteLength(reqParsed.body)}`);
      conn.write(`${lines.join('\r\n')}\r\n\r\n${reqParsed.body}`);
    });
    let raw = '';
    conn.on('data', (d) => (raw += d.toString('binary')));
    conn.on('error', reject);
    conn.on('close', () => {
      const sep = raw.indexOf('\r\n\r\n');
      // The raw bytes include the chunk framing; the header tells the parser so.
      resolve(parseHttpResponse(raw.slice(0, sep), Buffer.from(raw.slice(sep + 4), 'binary')));
    });
  });
}

const reqParsed = parseRawRequest(rawReq);
const live = await rawHttp(reqParsed);
console.log(`   live response: ${live.status} ${live.body.slice(0, 90)}`);
const held = evaluate(expr, bindings(live));
check('VULN-001 predicate holds against the vulnerable response', held, true);

// And the same predicate must NOT hold once the leak is gone.
const patched = parseHttpResponse('HTTP/1.1 401 Unauthorized\r\n', Buffer.from('{"error":"Invalid credentials"}'));
check('VULN-001 predicate fails against a patched response', evaluate(expr, bindings(patched)), false);

// ---- 5. predicate error handling ----------------------------------------
console.log('-- predicate errors');
let threw = false;
try {
  evaluate('json.nonexistent.deep', bindings(patched));
} catch {
  threw = true;
}
check('undefined member access raises rather than silently passing', threw, true);

server.close();
console.log(failures === 0 ? '\nALL HARNESS CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
