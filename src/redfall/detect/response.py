"""Response-shape defects: user enumeration and verbose error leakage.

* **`user_enumeration`** — an authentication path that answers differently
  depending on whether the account exists. The signal is *divergence*: two
  branches in one handler that return distinguishable messages ("no such user"
  against "wrong password"), which is what lets an attacker enumerate accounts.
* **`verbose_error`** — an error handler that returns an exception, traceback or
  internal path to the caller. (The route-posture detector catches the
  inline-return shape; this one catches a dedicated error handler, which is the
  more common layout and would otherwise be missed.)

**The distinction that keeps this honest.** A single 401 for every failure is
*not* enumeration — that is the correct implementation. The detector reports
only a *pair* of distinguishable failure branches within one function, which is
the shape that actually leaks. A test asserts it stays silent on the
constant-response sibling.
"""

from __future__ import annotations

import re
from typing import Iterator

from .types import Finding

# Failure messages an auth path might return, grouped by which question they
# answer. Two from *different* groups in one handler is the enumeration shape.
_ACCOUNT_EXISTS_MESSAGES = (
    "no such user",
    "user not found",
    "unknown user",
    "invalid user",
    "account does not exist",
    "user does not exist",
    "not registered",
    "unknown account",
)

_PASSWORD_WRONG_MESSAGES = (
    "wrong password",
    "invalid password",
    "incorrect password",
    "bad credentials",
    "invalid credentials",
    "password incorrect",
    "authentication failed",
)

# The two phrases are looked for anywhere in the handler, not only on a
# `return` line. The earlier version tried to walk a `return` statement to its
# string and kept landing on the dict *key* (`"error"`) rather than the message
# (`"no such user"`), which is a lesson about pattern-matching JSON builders:
# the string that carries meaning is not the first one after the call.
_ACCOUNT_PHRASES = re.compile(
    r"""(?i)["'`]([^"'`\n]{3,80})["'`]"""
)

_ERROR_HANDLER = re.compile(
    r"""(?xi)
    @\s*\w+\.errorhandler\s*\(\s*(?P<code>\d{3})?\s*\)
    \s*
    (?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)
    """
)

_LEAKY_RESPONSE = re.compile(
    r"""(?xi)
    (?:
        \b(?:str|repr)\s*\(\s*\w*(?:e|err|exc|error)\w*\s*\)
      | \b(?:traceback|format_exc|__traceback__)\b
      | \w+\.stack\b
      | \berr\.(?:message|stack)\b
      | \bexception\b[^\n]*\b(?:detail|message|args)\b
    )
    """
)

# A handler that only ever answers with one failure message is fine.
_ENDPOINT_HINT = re.compile(r"(?i)\b(login|signin|sign_in|authenticate|auth|register|reset)\b")


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _function_spans(text: str) -> list[tuple[str, int, int]]:
    """Every top-level function as ``(name, start, end)``."""
    starts = [
        (m.group(1), m.start())
        for m in re.finditer(
            r"(?m)^\s*(?:async\s+)?(?:def|function|export\s+(?:async\s+)?function)\s+(\w+)",
            text,
        )
    ]
    spans: list[tuple[str, int, int]] = []
    for index, (name, start) in enumerate(starts):
        end = starts[index + 1][1] if index + 1 < len(starts) else len(text)
        spans.append((name, start, end))
    return spans


def detect_response(path: str, text: str) -> Iterator[Finding]:
    """User enumeration and verbose error leakage."""
    for name, start, end in _function_spans(text):
        body = text[start:end]
        if not _ENDPOINT_HINT.search(name) and not _ENDPOINT_HINT.search(body[:200]):
            continue
        # Every string literal in the handler, so a message carried in a dict
        # is found wherever it sits rather than only where a return statement
        # happens to put it.
        messages = [m.group(1).lower() for m in _ACCOUNT_PHRASES.finditer(body)]
        if not messages:
            continue
        saw_exists = any(
            any(fragment in message for fragment in _ACCOUNT_EXISTS_MESSAGES)
            for message in messages
        )
        saw_wrong = any(
            any(fragment in message for fragment in _PASSWORD_WRONG_MESSAGES)
            for message in messages
        )
        if saw_exists and saw_wrong:
            # One handler answers "does this account exist" and "was the
            # password wrong" differently. That is the enumeration oracle.
            yield Finding(
                category="user_enumeration",
                file=path,
                line=_line_of(text, start),
                symbol=name,
                detail="the auth path distinguishes 'no such account' from 'wrong password'",
            )

    for match in _ERROR_HANDLER.finditer(text):
        handler = match.group(2)
        start = match.end()
        end = len(text)
        for next_name, next_start, _ in _function_spans(text):
            if next_start > start:
                end = next_start
                break
        body = text[start:end]
        leak = _LEAKY_RESPONSE.search(body)
        if leak:
            yield Finding(
                category="verbose_error",
                file=path,
                line=_line_of(text, match.start() + leak.start()),
                symbol=handler,
                detail="an error handler returns internal exception detail",
            )
