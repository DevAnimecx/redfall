"""The detector result type, in its own module to keep imports acyclic.

The package `__init__` imports every detector so `DETECTORS` can enumerate
them, and every detector needs `Finding`. Putting the type in `__init__` makes
that a cycle, so it lives here and both sides import it from one place.
"""

from __future__ import annotations

import re
from typing import Any, NamedTuple


class Finding(NamedTuple):
    """One detector hit: what, where, and how confident."""

    category: str
    file: str
    line: int
    symbol: str
    detail: str

    def to_row(self) -> dict[str, Any]:
        """The shape the recall scorer and the scan report both consume."""
        return {
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "symbol": self.symbol,
            "detail": self.detail,
        }


# Comment forms across the languages this project reads.
_LINE_COMMENT = re.compile(r"(?m)(?<![:\"'`])(?:#|//)[^\n]*$")
_BLOCK_COMMENT = re.compile(r"/\*[\s\S]*?\*/")


def without_comments(text: str) -> str:
    """Source with comments blanked, preserving every line's position.

    A detector that reads comments reads documentation as code, and this
    project's range targets document their own vulnerabilities in comments: an
    upload handler carries a comment naming the extension check that is missing,
    and that comment *satisfied* the check the detector looks for, so the
    detector stayed silent on a real bug. The comment was the reason the
    detector missed the thing the comment described.

    Comments are replaced by spaces rather than deleted, so byte offsets and
    therefore line numbers are unchanged and a finding still points at the line
    a human would open.
    """
    def blank(match: re.Match[str]) -> str:
        return " " * (match.end() - match.start())

    # Line comments first, so a `//` inside a block cannot desync the pairing.
    text = _LINE_COMMENT.sub(blank, text)
    return _BLOCK_COMMENT.sub(blank, text)
