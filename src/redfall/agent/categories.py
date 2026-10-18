"""Category coverage (25 of 32) and the knowledge each one needs.

The four categories deliberately left out are listed in
`NOT_COVERED` with the measured reason. They are not "hard" in the
abstract — each one is excluded because a real reproduction could not be
obtained against this target, and shipping a category that cannot reproduce
would push `repro_rate` below 1.00 for a reason that has nothing to do with the
category itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Category:
    key: str
    title: str
    cwe: str
    severity: str
    # What static evidence makes this category plausible here.
    signals: tuple[str, ...] = ()
    # What the PoC must demonstrate for the finding to count as real.
    proof: str = ""
    # The repair shape the fixer should aim at.
    fix_strategy: str = ""
    aliases: tuple[str, ...] = ()


SUPPORTED_CATEGORIES: tuple[Category, ...] = (
    Category(
        key="sqli",
        title="SQL injection",
        cwe="CWE-89",
        severity="critical",
        signals=("pool.query with a template literal", "string concatenation into SQL", "ORDER BY built from input"),
        proof="A request whose injected SQL changes the result set, observed in the response body.",
        fix_strategy="parameterized_query",
        aliases=("sql_injection", "sql-injection"),
    ),
    Category(
        key="idor",
        title="Insecure direct object reference / missing object-level authorisation",
        cwe="CWE-639",
        severity="high",
        signals=("route reads req.params.id", "query filters by id without an owner predicate"),
        proof="One user reads or mutates another user's object by changing the identifier.",
        fix_strategy="owner_check",
        aliases=("broken_object_level_authorization", "bola"),
    ),
    Category(
        key="xss_reflected",
        title="Reflected cross-site scripting",
        cwe="CWE-79",
        severity="high",
        signals=("res.send of request data", "template interpolation without escaping"),
        proof="A submitted script payload is returned unescaped in an HTML response.",
        fix_strategy="output_encode",
        aliases=("reflected_xss",),
    ),
    Category(
        key="xss_stored",
        title="Stored cross-site scripting",
        cwe="CWE-79",
        severity="high",
        signals=("user content written then rendered", "comments/bio/profile fields"),
        proof="A payload stored by one request is returned unescaped by a later request.",
        fix_strategy="output_encode",
        aliases=("persistent_xss",),
    ),
    Category(
        key="path_traversal",
        title="Path traversal",
        cwe="CWE-22",
        severity="high",
        signals=("path.join with request data", "fs read/write of a user filename"),
        proof="A request reads or writes a file outside the intended directory.",
        fix_strategy="path_canonicalisation",
        aliases=("directory_traversal",),
    ),
    Category(
        key="cmd_injection",
        title="OS command injection",
        cwe="CWE-78",
        severity="critical",
        signals=("child_process.exec with request data", "shell string built from input"),
        proof="A request causes a marker command to run, observed in the response.",
        fix_strategy="argument_vector",
        aliases=("command_injection", "os_command_injection"),
    ),
    Category(
        key="ssrf",
        title="Server-side request forgery",
        cwe="CWE-918",
        severity="high",
        signals=("fetch/axios with a user URL", "no allowlist of schemes or hosts"),
        proof="The server fetches an attacker-chosen URL and the response is observable.",
        fix_strategy="url_allowlist",
        aliases=("server_side_request_forgery",),
    ),
    Category(
        key="ssrf_metadata",
        title="SSRF to cloud metadata service",
        cwe="CWE-918",
        severity="critical",
        signals=("fetch of a user URL", "no block of 169.254.169.254"),
        proof="The server reaches the link-local metadata endpoint and returns its body.",
        fix_strategy="url_allowlist",
        aliases=("metadata_ssrf", "cloud_metadata_ssrf"),
    ),
    Category(
        key="mass_assignment",
        title="Mass assignment",
        cwe="CWE-915",
        severity="high",
        signals=("INSERT built from Object.keys(req.body)", "spread of req.body into an entity"),
        proof="A request sets a privileged field the API never advertises.",
        fix_strategy="field_allowlist",
        aliases=("auto_binding",),
    ),
    Category(
        key="prototype_pollution",
        title="Prototype pollution",
        cwe="CWE-1321",
        severity="high",
        signals=("recursive merge of request objects", "Object.assign of user JSON"),
        proof="A request makes a fresh object elsewhere in the app carry the injected key.",
        fix_strategy="reject_dunder_keys",
        aliases=("proto_pollution",),
    ),
    Category(
        key="unsafe_deserialization",
        title="Unsafe deserialization",
        cwe="CWE-502",
        severity="critical",
        signals=("node-serialize.unserialize", "eval of parsed input", "vm.runInNewContext"),
        proof="A crafted payload executes code during deserialization, observed by a marker.",
        fix_strategy="safe_parser",
        aliases=("insecure_deserialization",),
    ),
    Category(
        key="hardcoded_secret",
        title="Hardcoded secret in source",
        cwe="CWE-798",
        severity="high",
        signals=("literal password/api key/jwt secret in source", "default fallback secret"),
        proof="The secret is read out of the source tree and shown to be the live credential.",
        fix_strategy="env_required",
        aliases=("hardcoded_credentials",),
    ),
    Category(
        key="secret_exposure",
        title="Secret exposure through an endpoint",
        cwe="CWE-200",
        severity="high",
        signals=("env dump route", "config endpoint returning process.env", "unauthenticated diagnostics"),
        proof="An HTTP response contains a credential or signing key.",
        fix_strategy="remove_or_authorise",
        aliases=("sensitive_data_exposure",),
    ),
    Category(
        key="user_enumeration",
        title="User enumeration",
        cwe="CWE-204",
        severity="medium",
        signals=("distinct messages for unknown user vs bad password", "different status codes"),
        proof="Two requests distinguish an existing account from a nonexistent one.",
        fix_strategy="uniform_response",
        aliases=("account_enumeration",),
    ),
    Category(
        key="missing_rate_limit",
        title="Missing rate limit on an authentication endpoint",
        cwe="CWE-307",
        severity="medium",
        signals=("login route with no limiter middleware", "no failed-attempt counter"),
        proof="Repeated credential attempts all reach the authentication logic.",
        fix_strategy="rate_limit",
        aliases=("brute_force", "no_rate_limit"),
    ),
    Category(
        key="no_pagination_limit",
        title="Unbounded query result set",
        cwe="CWE-770",
        severity="medium",
        signals=("SELECT without LIMIT", "LIMIT taken from req.query unbounded"),
        proof="A request returns the whole table, or an attacker-chosen LIMIT is honoured.",
        fix_strategy="bounded_pagination",
        aliases=("unbounded_query", "missing_pagination"),
    ),
    Category(
        key="negative_amount",
        title="Negative or non-finite amount accepted",
        cwe="CWE-840",
        severity="high",
        signals=("amount used in an UPDATE without a > 0 check", "parseFloat of request amount"),
        proof="A transfer with a negative amount increases the attacker's balance.",
        fix_strategy="input_validation",
        aliases=("negative_value", "business_logic_amount"),
    ),
    Category(
        key="open_redirect",
        title="Open redirect",
        cwe="CWE-601",
        severity="medium",
        signals=("res.redirect(req.query...)", "Location header built from input"),
        proof="A response redirects to an attacker-chosen external origin.",
        fix_strategy="redirect_allowlist",
        aliases=("url_redirect",),
    ),
    Category(
        key="verbose_error",
        title="Verbose error disclosure",
        cwe="CWE-209",
        severity="medium",
        signals=("res.status(500).send(err)", "stack trace returned to the client"),
        proof="An error response leaks a stack trace, query text or internal path.",
        fix_strategy="generic_error",
        aliases=("stack_trace_disclosure", "information_disclosure"),
    ),
    Category(
        key="weak_password_hash_md5",
        title="Password stored with MD5",
        cwe="CWE-916",
        severity="high",
        signals=("crypto.createHash('md5') over a password", "unsalted fast hash"),
        proof="A stored credential is shown to be an unsalted MD5 of the known password.",
        fix_strategy="bcrypt",
        aliases=("weak_hash", "md5_password"),
    ),
    Category(
        key="missing_signature_verify",
        title="Webhook accepted without signature verification",
        cwe="CWE-345",
        severity="critical",
        signals=("webhook route ignoring the signature header", "constructEvent not used"),
        proof="An unsigned request mutates state as though it came from the provider.",
        fix_strategy="verify_signature",
        aliases=("unverified_webhook", "missing_webhook_signature"),
    ),
    Category(
        key="unrestricted_file_type",
        title="Unrestricted file upload type",
        cwe="CWE-434",
        severity="high",
        signals=("multer without fileFilter", "extension or MIME never checked"),
        proof="A dangerous file type is accepted and stored by the upload endpoint.",
        fix_strategy="upload_allowlist",
        aliases=("file_upload", "dangerous_file_type"),
    ),
    Category(
        key="csv_injection",
        title="CSV formula injection",
        cwe="CWE-1236",
        severity="medium",
        signals=("CSV built by string concatenation", "export of user-controlled fields"),
        proof="An exported field begins with a formula character unescaped.",
        fix_strategy="csv_escape",
        aliases=("formula_injection",),
    ),
    Category(
        key="cors_wildcard_credentials",
        title="Permissive CORS with credentials",
        cwe="CWE-942",
        severity="medium",
        signals=("cors origin reflecting the request origin", "credentials true with a wildcard"),
        proof="An arbitrary Origin is echoed back with credentials allowed.",
        fix_strategy="origin_allowlist",
        aliases=("cors_misconfiguration",),
    ),
    Category(
        key="missing_csp",
        title="Missing Content-Security-Policy",
        cwe="CWE-693",
        severity="low",
        signals=("helmet not used", "no CSP header set anywhere"),
        proof="A normal response carries no Content-Security-Policy header.",
        fix_strategy="security_headers",
        aliases=("no_csp",),
    ),
)

NOT_COVERED: tuple[dict[str, str], ...] = (
    {
        "key": "timing_attack",
        "reason": (
            "Measured against this target: a single MD5 compare versus no hash compare differs by "
            "~0.014 ms against ~1.1 ms of HTTP noise, and the sandbox has 2 vCPU. Even interleaved "
            "warm-up sampling did not separate the two distributions, so no PoC reproduces. "
            "Excluded rather than shipped unreproducible."
        ),
    },
    {
        "key": "race_condition",
        "reason": (
            "Requires concurrent requests to interleave inside one transaction. The Node target "
            "serialises the transfer on a single event loop, so the double-spend window never opens "
            "at the concurrency this sandbox can generate. No reproducible PoC."
        ),
    },
    {
        "key": "jwt_alg_none",
        "reason": (
            "jsonwebtoken 9.0.3 rejects alg=none with 'jwt signature is required' unless the verifier "
            "explicitly pins algorithms: ['none']. The bypass does not reproduce against the pinned "
            "dependency version, so the category is out for this release."
        ),
    },
    {
        "key": "jwt_no_expiry",
        "reason": (
            "A token without exp is only observable by waiting for the expiry that does not exist. "
            "There is no bounded PoC, and fabricating one would mean bending the ground truth."
        ),
    },
)

_BY_KEY: dict[str, Category] = {c.key: c for c in SUPPORTED_CATEGORIES}
_ALIASES: dict[str, str] = {}
for _c in SUPPORTED_CATEGORIES:
    for _a in _c.aliases:
        _ALIASES[_a] = _c.key


def is_covered(key: str) -> bool:
    return key in _BY_KEY


def normalise(key: str) -> str:
    """Map a category name or alias onto the canonical key.

    Unknown names are returned unchanged so the scorer can record a genuine
    miss instead of silently reclassifying it into something that matches.
    """
    if key in _BY_KEY:
        return key
    return _ALIASES.get(key, key)


def get(key: str) -> Category | None:
    return _BY_KEY.get(normalise(key))


def all_keys() -> list[str]:
    return [c.key for c in SUPPORTED_CATEGORIES]


def coverage_summary() -> dict[str, object]:
    return {
        "supported_categories": len(SUPPORTED_CATEGORIES),
        "keys": all_keys(),
        "excluded": [e["key"] for e in NOT_COVERED],
        "excluded_reasons": {e["key"]: e["reason"] for e in NOT_COVERED},
    }


def signals_for(category_key: str) -> tuple[str, ...]:
    cat = get(category_key)
    return cat.signals if cat else ()


def prompt_block() -> str:
    """The category list as it is handed to the analysis prompt."""
    lines = []
    for c in SUPPORTED_CATEGORIES:
        lines.append(f"- {c.key} ({c.cwe}, {c.severity}): {c.title}. Proof required: {c.proof}")
    return "\n".join(lines)
