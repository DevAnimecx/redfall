"""Weak cryptography and missing signature verification.

Two classes, both *API-misuse* rather than flow:

* **`weak_password_hash_md5`** — a password reaching MD5, SHA-1, or a bare
  digest with no salt. There is no request value to trace; the defect is which
  function the code calls.
* **`missing_signature_verify`** — a webhook or callback handler that reads a
  signed payload and never verifies the signature. This is the **absence**
  shape, and absences are the reason this module exists at all: the taint
  engine can only report what the code does, never what it fails to do.

The absence case is the hard one and it is handled honestly: the detector fires
only when a handler is *unmistakably* a signed-callback receiver — it reads a
signature header, or its route names a webhook — **and** contains no verification
call. Requiring positive evidence of the receiver before reporting the missing
check is what keeps this from flagging every route that takes a POST body.

**What it misses.** A password hashed through an indirection the detector does
not resolve. A webhook verified in middleware the handler does not show. Both
are false-negative shapes that a whole-program analysis would catch and this
does not, and naming them is cheaper than pretending they do not exist.
"""

from __future__ import annotations

import re
from typing import Iterator

from .types import Finding

# Weak digest primitives. Matched on the dotted call so `hashlib.md5(` and
# `crypto.createHash('md5')` both land.
_WEAK_DIGEST = re.compile(
    r"""(?xi)
    (?:
        (?:hashlib|hash|crypto|crypt)\.(md5|sha1|sha-1)\s*\(
      | createHash\s*\(\s*["'](md5|sha1|sha-1)["']
      | \b(md5|sha1)\s*\(
    )
    """
)

# A project-local wrapper whose *name* declares a weak primitive —
# `md5_hex`, `sha1_hash`, `hashMD5`. Real codebases wrap the stdlib call in a
# helper, and a detector that only matched `hashlib.md5(` reported where the
# helper is defined rather than where a password is actually hashed, which is
# the line a reviewer needs to open.
_WEAK_WRAPPER_CALL = re.compile(
    r"""(?xi)
    \b([a-z_][a-z0-9_]*\.)?          # optional module/object prefix
    (md5|sha1|sha_1|sha_1_hex)[a-z0-9_]*\s*\(
    """
)

# Names that indicate the digest is being applied to a password.
_PASSWORD_CONTEXT = re.compile(
    r"(?i)\b(password|passwd|pwd|passphrase|secret|credential|pin)\b"
)

# A salt call — its presence means the digest is salted, which is a different
# and much weaker finding than an unsalted one, so it is not reported here.
_SALT_CALL = re.compile(r"(?i)\b(salt|bcrypt|scrypt|argon2|pbkdf2|gensalt)\b")

# A handler that reads a signature header from the request.
_SIG_HEADER_READ = re.compile(
    r"""(?xi)
    (?:headers?\.get\s*\(|headers?\s*\[|\.header\s*\(|req\.get\s*\()
    \s*["']([a-z0-9-]*signature[a-z0-9-]*)["']
    """
)

# Any verification of that header.
_VERIFY_CALL = re.compile(
    r"""(?xi)
    (?:
        (?:hmac|hashlib)\.compare_digest\b
      | verify\s*\(          # jsonwebtoken / webhook libs
      | constructEvent\b     # stripe
      | check_signature\b
      | validate_signature\b
      | \bhmac\b[^\n]*\bnew\b
    )
    """
)

# Route decorators that mark a signed-callback receiver.
_WEBHOOK_ROUTE = re.compile(
    r"""(?xi)
    @\w+\.(?:route|post|get)\s*\(\s*["'][^"']*\b(webhook|callback|hook|notify|stripe|github)\b
    """
)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _enclosing_function(text: str, index: int) -> str:
    prefix = text[:index]
    matches = list(
        re.finditer(
            r"(?m)^\s*(?:def|async\s+def|function|export\s+(?:async\s+)?function|const|let|var|fun)\s+([A-Za-z_][A-Za-z0-9_]*)",
            prefix,
        )
    )
    return matches[-1].group(1) if matches else ""


def _function_span(text: str, index: int) -> tuple[int, int]:
    """The byte span of the function containing ``index``.

    A pragmatic span: from the nearest preceding `def`/`function` to the next
    one at the same or lower indentation. Good enough to ask "does the body
    that reads this header contain a verification", which is the only question
    the detector asks of it.
    """
    starts = [
        m.start()
        for m in re.finditer(r"(?m)^\s*(?:def|async\s+def|function|export\s+(?:async\s+)?function)\s+", text)
    ]
    before = [s for s in starts if s <= index]
    start = before[-1] if before else 0
    after = [s for s in starts if s > index]
    end = after[0] if after else len(text)
    return start, end


def detect_crypto(path: str, text: str) -> Iterator[Finding]:
    """Weak password hashing, and signed callbacks with no verification."""
    # --- weak password hash ---
    # Both the stdlib call and a project-local wrapper whose name declares the
    # primitive. The wrapper arm is what finds the bug where a reviewer needs
    # to see it: the call site that hashes a password, not the helper's
    # definition, which may be used for non-secret work elsewhere.
    seen_lines: set[int] = set()
    for pattern in (_WEAK_DIGEST, _WEAK_WRAPPER_CALL):
        for match in pattern.finditer(text):
            line_no = _line_of(text, match.start())
            if line_no in seen_lines:
                continue
            start, end = _function_span(text, match.start())
            body = text[start:end]
            if _SALT_CALL.search(body):
                # A salted digest is unusual but not the bug this class names.
                continue
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.start())
            line = text[line_start : line_end if line_end != -1 else len(text)]
            if not (_PASSWORD_CONTEXT.search(line) or _PASSWORD_CONTEXT.search(body)):
                continue
            seen_lines.add(line_no)
            yield Finding(
                category="weak_password_hash_md5",
                file=path,
                line=line_no,
                symbol=_enclosing_function(text, match.start()),
                detail="a password is digested with a weak, unsalted primitive",
            )

    # --- missing signature verification ---
    for match in _SIG_HEADER_READ.finditer(text):
        header = match.group(1)
        start, end = _function_span(text, match.start())
        body = text[start:end]
        if _VERIFY_CALL.search(body):
            continue
        yield Finding(
            category="missing_signature_verify",
            file=path,
            line=_line_of(text, match.start()),
            symbol=_enclosing_function(text, match.start()),
            detail=f"{header} is read but never verified in this handler",
        )

    # A webhook route whose handler never verifies anything at all.
    for match in _WEBHOOK_ROUTE.finditer(text):
        start, end = _function_span(text, match.end())
        body = text[start:end]
        if _VERIFY_CALL.search(body) or _SIG_HEADER_READ.search(body):
            continue
        # Only report when the body actually takes a payload — a webhook route
        # that reads nothing cannot have an unverified payload.
        if not re.search(r"(?i)\b(body|payload|data|request\.(?:json|data|body))\b", body):
            continue
        yield Finding(
            category="missing_signature_verify",
            file=path,
            line=_line_of(text, match.start()),
            symbol=_enclosing_function(text, match.end()),
            detail="a webhook handler accepts a payload with no signature check",
        )
