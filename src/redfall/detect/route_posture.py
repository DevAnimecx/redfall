"""Route posture: four classes that are the *absence* of a check.

Every other detector in this package reports something the code does. This one
reports something the code fails to do, which is why taint analysis can never
reach it: there is no value to trace, only a missing guard.

* **`missing_rate_limit`** — a mutating route with no limiter in its decorator
  chain or handler.
* **`idor`** — a route that takes an object identifier from the path or query
  and returns or mutates a record, with no ownership check binding the
  identifier to the caller.
* **`unrestricted_file_type`** — an upload handler that stores a caller-named
  file without checking its extension or content type.
* **`verbose_error`** — a handler that returns an exception string or a
  traceback to the caller.

**The false-positive problem, faced rather than fudged.** A detector for an
absence fires on every route unless it is careful, and a scanner that flags
every endpoint is one nobody reads. Each rule below therefore requires positive
evidence that the route is the *kind* of route that needs the check:

* rate limiting is only expected on a mutating verb (POST/PUT/PATCH/DELETE),
* IDOR is only reported when the handler demonstrably fetches or mutates a
  record *by* that identifier,
* an upload must actually save a caller-named file.

A route that merely exists is never a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from .types import Finding

# --- route discovery -------------------------------------------------------

# Flask/FastAPI style: @bp.post("/upload"), @app.route("/x", methods=["POST"])
_PY_ROUTE = re.compile(
    r"""(?xi)
    @\s*(\w+)\.(route|get|post|put|patch|delete|head|options)\s*\(
      \s*["']([^"']+)["']
      (?P<rest>[^)]*)
    \)
    \s*
    (?:@\w+[^\n]*\n\s*)*            # other decorators may follow
    (?:async\s+)?def\s+(\w+)
    """
)

# Express style: router.post('/x', handler) / app.get('/x', h)
_TS_ROUTE = re.compile(
    r"""(?xi)
    \b(?:router|app|server|api|bp|fastify)\s*\.\s*(get|post|put|patch|delete|all)\s*\(
      \s*["']([^"']+)["']
      \s*,\s*
      (?:async\s+)?(?:function\s+)?(\w+)?
    """
)

_MUTATING = {"post", "put", "patch", "delete"}

# Routes that need a limiter for a reason other than writing: the
# authentication surface, which credential stuffing attacks directly.
_AUTH_ENDPOINT = re.compile(
    r"(?i)\b(login|signin|sign_in|sign-in|authenticate|auth|register|signup|"
    r"sign_up|reset|forgot|verify|token|otp|mfa|2fa)\b"
)

# Signs that a route is protected by a limiter.
_RATE_LIMIT = re.compile(
    r"(?i)\b(rate_?limit|limiter|throttle|slowapi|express-rate-limit|ratelimit)\b"
)

# An identifier taken from the path (`<int:user_id>`, `:id`) or a query read.
_PATH_ID = re.compile(r"(?i)<(?:int|string|uuid|path)?:?(\w*id\w*)>|:(\w*id\w*)\b")
_QUERY_ID = re.compile(r"""(?i)request\.args\.get\s*\(\s*["'](\w*id\w*)["']|req\.query\.(\w*id\w*)""")

# The handler demonstrably touching a record by that identifier. The SQL arm
# allows newlines inside the statement because a formatter routinely wraps it,
# and a pattern that stops at the line break misses exactly that code.
_RECORD_FETCH = re.compile(
    r"""(?xi)
    (?:
        \b(?:SELECT|UPDATE|DELETE|INSERT)\b(?:(?!;)[\s\S]){0,400}?\bWHERE\b
            (?:(?!;)[\s\S]){0,200}?\bid\b
      | \b(?:findById|findOne|findByPk|getById|find_by_id)\s*\(
      | \.get\s*\([^)]*\bid\b
    )
    """
)

# An ownership binding: the identifier checked against the caller.
_OWNERSHIP_CHECK = re.compile(
    r"""(?xi)
    (?:
        \b(?:owner|user|account|tenant|principal|current_user|req\.user)\w*\s*(?:==|===|!=|!==)\s*\w*
      | \w*\s*(?:==|===|!=|!==)\s*\b(?:owner|current_user|req\.user|session)\w*
      | \b(?:owns|can_access|authorize|authorise|is_owner|assert_owner|check_owner)\b
    )
    """
)

_UPLOAD_ROUTE = re.compile(
    r"""(?i)\b(upload|file)\b[^\n]*\n(?:[^\n]*\n){0,30}?"""
)

# A caller-supplied filename reaching a save. The access is commonly split
# across lines — `target = UPLOAD_DIR / file.filename` on one, the save on the
# next — so the pattern reads the whole body rather than a single line.
_CALLER_FILENAME = re.compile(
    r"""(?xi)
    (?:
        \.filename\b
      | \.originalname\b
      | \.original_filename\b
    )
    """
)

# The file is actually written, which is what makes an unchecked name a
# finding rather than a variable that merely exists.
_FILE_SAVE = re.compile(
    r"""(?xi)
    (?:
        \.save\s*\(
      | \.write\s*\(
      | shutil\.copy(?:file)?\s*\(
      | fs\.write(?:File|FileSync)?\s*\(
      | \bopen\s*\([^)]*["']w
    )
    """
)

_TYPE_CHECK = re.compile(
    r"""(?xi)
    (?:
        \b(?:allowed|permitted|whitelist|allowlist)\w*\b
      | \b(?:mimetype|content_type|content-type|extension|extname|splitext)\b
      | \.ends_with\s*\(          # rust/kotlin
      | \bendswith\s*\(           # python
    )
    """
)

# A fetch of a caller-named URL: the HTTP call itself.
_UNRESTRICTED_FETCH = re.compile(
    r"""(?xi)
    (?:
        \b(?:requests|httpx|aiohttp)\.(?:get|post|put|delete|request)\s*\(
      | \burlopen\s*\(
      | \bfetch\s*\(
      | \baxios\.(?:get|post)\s*\(
      | \bhttp\.get\s*\(
    )
    """
)

# The URL came from the request rather than from configuration.
_REQUEST_DERIVED_URL = re.compile(
    r"""(?xi)
    (?:
        \b(?:url|uri|target|endpoint|link|dest|destination|next)\w*\s*=\s*[^\n]*
        (?:request\.|req\.|params|query|payload)
      | (?:request\.|req\.)(?:args|query|json|body|params)[^\n]*\b(?:url|uri|target|link|dest)\b
    )
    """
)

# Any check on the destination host or address. Its presence means the fetch is
# constrained, so the metadata range is not automatically reachable.
_HOST_RESTRICTION = re.compile(
    r"""(?xi)
    (?:
        \b(?:allowlist|whitelist|allowed_hosts|allowed_domains|blocklist|denylist)\b
      | 169\.254\.169\.254
      | \bmetadata\.google\.internal\b
      | \burlparse\s*\([^\n]*\.hostname
      | \b(?:host|hostname|netloc)\s+(?:not\s+)?in\s
      | \b(?:is_private|ip_address|ipaddress)\b
      | \bscheme\s*(?:==|!=|in)\s
    )
    """
)

_TRACEBACK_RETURN = re.compile(
    r"""(?xi)
    (?:
        (?:return|jsonify|res\.(?:json|send)|response)\s*[\(\[{]?[^\n;]*
        \b(?:traceback|format_exc|\.stack|err\.stack|exception|e\.message|str\(e\)|repr\(e\))\b
      | \bformat_exc\s*\(
    )
    """
)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


@dataclass(frozen=True)
class _Route:
    verb: str
    path: str
    handler: str
    body: str
    body_start: int
    decorators: str


def _routes(text: str) -> list[_Route]:
    """Every route in the file, with the body span each one governs."""
    found: list[_Route] = []

    for match in _PY_ROUTE.finditer(text):
        verb = match.group(2).lower()
        decorators = match.group(0)
        if verb == "route":
            rest = match.group("rest") or ""
            verbs = re.search(r"""(?i)methods\s*=\s*\[([^\]]*)\]""", rest)
            if verbs:
                listed = re.findall(r"""["'](\w+)["']""", verbs.group(1))
                verb = listed[0].lower() if listed else "get"
            else:
                verb = "get"
        handler = match.group(5)
        start, end = _body_span(text, match.end())
        found.append(
            _Route(verb, match.group(3), handler, text[start:end], start, decorators)
        )

    for match in _TS_ROUTE.finditer(text):
        verb = match.group(1).lower()
        handler = match.group(3) or ""
        start, end = _body_span(text, match.end())
        found.append(
            _Route(verb, match.group(2), handler, text[start:end], start, match.group(0))
        )

    return found


def _body_span(text: str, from_index: int) -> tuple[int, int]:
    """The extent of the handler body, from just after its declaration.

    The span runs to the next top-level route or function declaration. It is a
    pragmatic boundary: the question every rule here asks is "does the code
    that serves this route contain X", and a span that reaches slightly too far
    can only produce a false *negative* for an absence check, never a false
    positive.
    """
    starters = [
        m.start()
        for m in re.finditer(
            r"(?m)^\s*(?:@\s*\w+\.(?:route|get|post|put|patch|delete)\b|def\s|async\s+def\s|function\s|export\s+(?:async\s+)?function\s|const\s+\w+\s*=\s*(?:async\s*)?\()",
            text,
        )
    ]
    after = [s for s in starters if s > from_index]
    end = after[0] if after else len(text)
    return from_index, min(end, from_index + 4000)


def detect_route_posture(path: str, text: str) -> Iterator[Finding]:
    """Rate limiting, object authorisation and upload checks — by absence."""
    for route in _routes(text):
        decorator_text = route.decorators
        body = route.body

        # --- missing_rate_limit ---
        # Two kinds of route need a limiter, and gating on mutation alone
        # missed the second: a route that writes, and a route that
        # authenticates. A login endpoint mutates nothing — it reads a user and
        # compares a hash — and it is the single most rate-limited route in any
        # real service, because it is what credential stuffing targets.
        if route.verb in _MUTATING or _AUTH_ENDPOINT.search(
            f"{route.handler} {route.path}"
        ):
            if not (_RATE_LIMIT.search(decorator_text) or _RATE_LIMIT.search(body)):
                writes = bool(
                    re.search(
                        r"(?i)\b(INSERT|UPDATE|DELETE|save|commit|create|update|remove)\b",
                        body,
                    )
                )
                authenticates = bool(_AUTH_ENDPOINT.search(f"{route.handler} {route.path}"))
                if writes or authenticates:
                    why = (
                        f"{route.verb.upper()} {route.path} authenticates with no limiter"
                        if authenticates
                        else f"{route.verb.upper()} {route.path} mutates with no limiter"
                    )
                    yield Finding(
                        category="missing_rate_limit",
                        file=path,
                        line=_line_of(text, route.body_start),
                        symbol=route.handler,
                        detail=why,
                    )

        # --- idor ---
        id_in_path = _PATH_ID.search(route.path)
        id_query = _QUERY_ID.search(body)
        if id_in_path or id_query:
            ident = (id_in_path.group(1) or id_in_path.group(2)) if id_in_path else None
            if ident is None and id_query:
                ident = id_query.group(1) or id_query.group(2)
            fetches = bool(_RECORD_FETCH.search(body))
            guarded = bool(_OWNERSHIP_CHECK.search(body))
            if ident and fetches and not guarded:
                yield Finding(
                    category="idor",
                    file=path,
                    line=_line_of(text, route.body_start),
                    symbol=route.handler,
                    detail=f"{route.path} reads a record by {ident} with no ownership check",
                )

        # --- unrestricted_file_type ---
        if _CALLER_FILENAME.search(body) and _FILE_SAVE.search(body):
            if not _TYPE_CHECK.search(body):
                yield Finding(
                    category="unrestricted_file_type",
                    file=path,
                    line=_line_of(text, route.body_start),
                    symbol=route.handler,
                    detail="a caller-named upload is stored with no type or extension check",
                )

        # --- verbose_error ---
        trace = _TRACEBACK_RETURN.search(body)
        if trace:
            yield Finding(
                category="verbose_error",
                file=path,
                line=_line_of(text, route.body_start + trace.start()),
                symbol=route.handler,
                detail="an exception detail is returned to the caller",
            )

        # --- ssrf, and its metadata variant ---
        # A fetch whose target comes from the request, with no host or address
        # restriction, reaches the cloud metadata service by construction —
        # 169.254.169.254 is simply one more URL the caller may name. The
        # corpus models these as two classes because the *impact* differs
        # (instance credentials rather than a proxied response), but they are
        # one defect in the code, at one line, and both are reported from here.
        if _UNRESTRICTED_FETCH.search(body) and _REQUEST_DERIVED_URL.search(body):
            if not _HOST_RESTRICTION.search(body):
                line = _line_of(text, route.body_start + _UNRESTRICTED_FETCH.search(body).start())
                yield Finding(
                    category="ssrf",
                    file=path,
                    line=line,
                    symbol=route.handler,
                    detail="a request-named URL is fetched with no host restriction",
                )
                yield Finding(
                    category="ssrf_metadata",
                    file=path,
                    line=line,
                    symbol=route.handler,
                    detail=(
                        "the same unrestricted fetch reaches the link-local metadata "
                        "range, so instance credentials are readable"
                    ),
                )
