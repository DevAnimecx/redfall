"""Detectors for the vulnerability classes taint analysis cannot reach.

Taint analysis finds *flows*: a request value reaching a dangerous call. Nine of
the classes this project seeds are not flows at all, and no amount of taint
depth reaches them — a hardcoded secret is a literal, a missing rate limit is an
absence, an IDOR is a missing authorisation check, a verbose error is a response
shape.

Each module here is a detector for one such shape. They share three rules:

**A detector is a pure function.** It takes a source file's text and returns
findings. It does not run the target, does not touch the network, and does not
mutate anything. That makes each one testable in isolation and fast enough to
run over every file in a scan.

**A detector states where it looked.** Every finding carries the file, the
line and the symbol, because a finding without a location cannot be reproduced
and this project does not report those.

**A detector is allowed to miss.** A regex over source text will produce false
positives on unusual code; the honest response is to keep the pattern narrow and
document what it does not catch, rather than to widen it until precision
collapses. The safe sibling of every seeded flow gets a test asserting the
detector stays quiet on it.
"""

from __future__ import annotations

from typing import Callable, Iterable

from .crypto import detect_crypto
from .encoding import detect_encoding
from .response import detect_response
from .route_posture import detect_route_posture
from .secrets import detect_secrets
from .types import Finding, without_comments

#: Every detector, as (name, callable). The callable takes ``(path, text)`` and
#: returns an iterable of Findings. Order is stable so output is reproducible.
DETECTORS: tuple[tuple[str, Callable[[str, str], Iterable[Finding]]], ...] = (
    ("secrets", detect_secrets),
    ("crypto", detect_crypto),
    ("route_posture", detect_route_posture),
    ("response", detect_response),
    ("encoding", detect_encoding),
)


def detect_file(path: str, text: str) -> list[Finding]:
    """Run every detector over one file, deduplicated and ordered.

    Deduplicated because two detectors can legitimately flag the same line for
    related reasons (a secret that is also exposed), and reporting it twice
    inflates the invented rate without telling anyone anything new.
    """
    # Comments are blanked first: a comment naming the guard a detector looks
    # for would otherwise satisfy that detector, and this project's own range
    # targets document their vulnerabilities in exactly that way.
    code = without_comments(text)
    found: dict[tuple[str, str, int], Finding] = {}
    for _name, detector in DETECTORS:
        try:
            hits = detector(path, code)
        except Exception:  # noqa: BLE001 - one bad detector must not end a scan
            # A detector that raises on unusual source must not fail the scan.
            # Swallowing is deliberate: a missed detection is reported as a
            # miss, whereas a crash would look like the engine found nothing.
            continue
        for hit in hits:
            found.setdefault((hit.category, hit.file, hit.line), hit)
    return sorted(found.values(), key=lambda f: (f.file, f.line, f.category))


def detect_tree(files: Iterable[tuple[str, str]]) -> list[Finding]:
    """Run every detector over a sequence of ``(path, text)`` pairs."""
    out: list[Finding] = []
    for path, text in files:
        out.extend(detect_file(path, text))
    return out


__all__ = [
    "DETECTORS",
    "Finding",
    "detect_crypto",
    "detect_encoding",
    "detect_file",
    "detect_response",
    "detect_route_posture",
    "detect_secrets",
    "detect_tree",
]
