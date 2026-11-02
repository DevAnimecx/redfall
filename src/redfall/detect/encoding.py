"""Output-encoding defects: CSV injection.

**`csv_injection`** — a request value written into a CSV cell unescaped. A
spreadsheet reads a leading `=`, `+`, `-`, `@`, tab or carriage return as a
formula, so a crafted value becomes a command in the reader's spreadsheet. It is
not a flow to a dangerous *call* in the sense taint models — the sink is a
spreadsheet application on someone else's desk — and the mitigation is an
encoding step, which is why it lives here rather than in the taint engine.

**What makes this reportable rather than noise.** A CSV writer that only ever
writes literals is fine. The detector requires positive evidence that a
*request-derived* value reaches the row, and that no formula-prefix guard is
applied. The regex asks for the request read and the writer call in the same
function, with no sanitising step between them.

**What it misses.** A value that reaches the writer through several functions,
and a guard applied in a helper. Both are the usual false-negative shape for a
single-file detector.
"""

from __future__ import annotations

import re
from typing import Iterator

from .types import Finding

# A CSV writer call, in any of the forms the mainstream libraries use.
_CSV_WRITE = re.compile(
    r"""(?xi)
    (?:
        writer\.writerow\s*\(
      | writer\.writerows\s*\(
      | csv\.writer\s*\(
      | \bcsv\s*\.\s*stringify\s*\(
      | \bto_csv\s*\(
    )
    """
)

# Hand-rolled CSV: an f-string row with comma-separated interpolations, pushed
# into a list. This is the shape a large share of real exporters use — the
# `csv` module is not always involved — and it is why a detector that only
# looked for `writer.writerow` found nothing on the seeded flow.
#
# Written as two independent signals rather than one clever pattern: an append
# of an f-string, and that f-string holding a comma between two `{...}`
# substitutions. Composing it that way survived the shaping that broke a
# single-expression version.
_CSV_APPEND_FSTRING = re.compile(r"""(?i)(?:append|push)\s*\(\s*f["']""")
_FSTRING_ROW_SHAPE = re.compile(r"""(?i)f["'][^\n]*\{[^}\n]+\}[^\n]*,[^\n]*\{[^}\n]+\}""")

# A response declaring a CSV content type, which is what makes a comma-joined
# string an actual export rather than a debug log line.
_CSV_RESPONSE = re.compile(
    r"""(?xi)
    (?:
        ["']text/csv["']
      | \bmimetype\s*=\s*["']text/csv["']
      | \bcontent-type["']\s*,\s*["']text/csv
      | \.csv["']
    )
    """
)

# A value derived from the request.
_REQUEST_VALUE = re.compile(
    r"""(?xi)
    (?:
        request\.(?:args|form|json|values|get_json|files|headers)\b
      | req\.(?:body|query|params|headers)\b
      | \bparams\s*\[
      | c\.(?:request|params|query)\b
    )
    """
)

# A guard against spreadsheet formula interpretation.
_FORMULA_GUARD = re.compile(
    r"""(?xi)
    (?:
        [\(\[]\s*["']?[=+\-@\t\r]["']?
      | \b(?:escape|sanitize|sanitise|quote|csv_safe|formula_safe|defuse)\w*
      | \bstartswith\s*\(\s*\(?\s*["'][=+\-@]
      | \breplace\s*\(\s*["']\s*["']\s*,\s*["']\s*["']
    )
    """
)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _function_spans(text: str) -> list[tuple[str, int, int]]:
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


def detect_encoding(path: str, text: str) -> Iterator[Finding]:
    """CSV formula injection, through a writer or a hand-rolled row."""
    for name, start, end in _function_spans(text):
        body = text[start:end]
        if _FORMULA_GUARD.search(body):
            # A guard anywhere in the function covers its rows.
            continue

        writer = _CSV_WRITE.search(body)
        hand_rolled = (
            _CSV_APPEND_FSTRING.search(body) or _FSTRING_ROW_SHAPE.search(body)
        )
        if not (writer or hand_rolled):
            continue

        # A hand-rolled row is only an export when something declares a CSV
        # content type; otherwise it is a log line and not this class.
        if hand_rolled and not writer and not _CSV_RESPONSE.search(body):
            continue

        # The value written must be derived from stored or request data. Rows
        # built entirely from literals cannot carry an attacker-chosen formula.
        source = _REQUEST_VALUE.search(body)
        if not source and not re.search(
            r"(?i)\b(row|record|rows|records|item|items)\s*\[", body
        ):
            continue

        anchor = (writer or hand_rolled).start()
        yield Finding(
            category="csv_injection",
            file=path,
            line=_line_of(text, start + anchor),
            symbol=name,
            detail="a data-derived value is written to CSV with no formula guard",
        )
