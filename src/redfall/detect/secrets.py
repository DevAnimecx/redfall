"""Hardcoded secrets, and secrets served to a caller.

Two classes, both literal-shaped rather than flow-shaped:

* **`hardcoded_secret`** — a credential committed in the source. No request
  value is involved; there is nothing to trace. The signal is a
  secret-suggesting name bound to a literal that looks like a credential.
* **`secret_exposure`** — that secret, or an environment variable matching a
  secret-shaped name, handed back in a response. Here there *is* a flow, but it
  is not attacker-controlled data reaching a sink — it is the project's own
  credential reaching a caller, so the taint engine has no source to start from.

**What this deliberately does not flag.** A name containing `key` or `token` is
not itself a finding: `token_type = "Bearer"` is a name match with a harmless
value, and flagging it is how a secret scanner trains its users to ignore it.
The literal must also look like a credential — long enough, and either
high-entropy or drawn from the placeholder vocabulary that ships in real code
(`do-not-ship`, `changeme`, `example`). Both halves are required.

**What it misses, stated rather than discovered.** Base64-encoded secrets below
the entropy bar, secrets built by concatenation, and secrets read from a file
at runtime are not caught here.
"""

from __future__ import annotations

import math
import re
from typing import Iterator

from .types import Finding

# Assignments whose target names suggest a credential.
#
# The name is matched as a whole identifier and tested separately rather than
# baked into one expression. The single-expression version silently failed on
# `API_KEY`: the leading `[A-Za-z0-9_]*` consumed the entire name only once, so
# there was no backtrack point left for the keyword alternation to match, and
# the pattern returned nothing for a name it plainly should have caught. Two
# smaller patterns are easier to be sure of than one clever one.
_CREDENTIAL_NAME = re.compile(
    r"(?i)\b(?:SECRET|PASSWORD|PASSWD|PWD|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|SIGNING[_-]?KEY)"
)

_ASSIGNMENT = re.compile(
    r"""(?xi)
    \b([A-Za-z_][A-Za-z0-9_]*)\s*          # the target name
    (?:=|:=|:)\s*                          # any of py/js/kotlin assignment
    (["'`])                                # a literal opens
    ([^"'`\n]{4,})                         # its body
    \2
    """
)

# Words that mark a literal as a placeholder rather than a live credential.
# Their presence is a signal *for* reporting: real code shipped with
# "do-not-ship" in it is exactly the bug this class describes.
_PLACEHOLDER_HINTS = (
    "do-not-ship",
    "dont-ship",
    "changeme",
    "change-me",
    "example",
    "placeholder",
    "insecure",
    "default-secret",
    "test-secret",
    "dev-secret",
    "hardcoded",
    "todo",
)

# A response call that returns a value built from a secret-named symbol.
_HANDLER_RETURNING = re.compile(
    r"""(?ix)
    (?:return|jsonify|res\.json|response\.json|json\.dumps)\s*[\(\[{]?[^;\n]*
    \b([A-Za-z_][A-Za-z0-9_]*SECRET[A-Za-z0-9_]*)
    """,
)

# Environment reads whose variable name marks the value as sensitive.
_ENV_SECRET = re.compile(
    r"""(?ix)
    (?:os\.environ(?:\.get)?\s*(?:\(\s*)?|getenv\s*\(\s*|process\.env\.)
    (["'])([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY)[A-Z0-9_]*)\1
    """,
)

# A response that echoes a whole environment mapping.
_ENV_DUMP = re.compile(
    r"(?i)(os\.environ\b|process\.env\b)[^;\n]*\b(items\(\)|\.\.\.|Object\.(?:keys|entries))"
)


def _entropy(text: str) -> float:
    """Shannon entropy per character. A random credential scores high."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _looks_like_a_credential(value: str) -> tuple[bool, str]:
    """Whether a literal is worth reporting, and why.

    Requiring *both* a credential-shaped name and a credential-shaped value is
    what separates this from a name-only matcher that flags every `key = "..."`.
    """
    lowered = value.lower()
    for hint in _PLACEHOLDER_HINTS:
        if hint in lowered:
            return True, f"placeholder credential ({hint})"
    if len(value) >= 16 and _entropy(value) >= 3.2:
        return True, f"high-entropy literal ({_entropy(value):.1f} bits/char, {len(value)} chars)"
    return False, ""


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _enclosing_function(text: str, index: int) -> str:
    """The name of the innermost function declaration above ``index``.

    A deliberately simple backward scan: it finds the nearest preceding `def`,
    `function`, or `=>`-bearing declaration. Good enough to name the symbol in
    a finding, which is all it is for.
    """
    prefix = text[:index]
    matches = list(
        re.finditer(
            r"(?m)^\s*(?:def|async\s+def|function|const|let|var|fun|public|private)\s+([A-Za-z_][A-Za-z0-9_]*)",
            prefix,
        )
    )
    return matches[-1].group(1) if matches else ""


def detect_secrets(path: str, text: str) -> Iterator[Finding]:
    """Hardcoded credentials and secrets served to a caller."""
    seen: set[tuple[str, int]] = set()

    for match in _ASSIGNMENT.finditer(text):
        name, _quote, value = match.group(1), match.group(2), match.group(3)
        if not _CREDENTIAL_NAME.search(name):
            continue
        credible, why = _looks_like_a_credential(value)
        if not credible:
            continue
        key = ("hardcoded_secret", _line_of(text, match.start()))
        if key in seen:
            continue
        seen.add(key)
        yield Finding(
            category="hardcoded_secret",
            file=path,
            line=key[1],
            symbol=name,
            detail=f"{name} is a committed credential: {why}",
        )

    # A secret-named symbol returned from a handler.

    # A secret-named symbol returned from a handler.
    for match in _HANDLER_RETURNING.finditer(text):
        name = match.group(1)
        line = _line_of(text, match.start())
        key = ("secret_exposure", line)
        if key in seen:
            continue
        seen.add(key)
        yield Finding(
            category="secret_exposure",
            file=path,
            line=line,
            symbol=_enclosing_function(text, match.start()),
            detail=f"a response returns {name}",
        )

    # A response that echoes the environment. The whole environment is an
    # exposure whether or not any single variable is named as a secret, since
    # deployment environments carry credentials under names this cannot know.
    for match in _ENV_DUMP.finditer(text):
        line = _line_of(text, match.start())
        if ("secret_exposure", line) in seen:
            continue
        seen.add(("secret_exposure", line))
        yield Finding(
            category="secret_exposure",
            file=path,
            line=line,
            symbol=_enclosing_function(text, match.start()),
            detail="a response echoes the process environment",
        )

    # An environment read of a secret-named variable, where the value is then
    # returned. Reported only when a return of the same name appears, so a
    # legitimate internal read is not flagged.
    for match in _ENV_SECRET.finditer(text):
        var = match.group(2)
        if re.search(rf"(?m)^\s*(?:return|jsonify)\b[^\n]*\b{re.escape(var)}\b", text):
            line = _line_of(text, match.start())
            if ("secret_exposure", line) in seen:
                continue
            seen.add(("secret_exposure", line))
            yield Finding(
                category="secret_exposure",
                file=path,
                line=line,
                symbol=_enclosing_function(text, match.start()),
                detail=f"the environment variable {var} is returned to a caller",
            )
