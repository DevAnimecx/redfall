"""Return-flow taint: a helper that reads a source and returns it.

The intraprocedural pass stops at the function boundary; the param-seeded half
of the interprocedural pass proves taints that travel *into* a callee. This
suite pins the third direction — sources travelling *out* of a callee through
its return value — with the same doctrine as everything else:

* only what can be proved is claimed (a return of a real source, or of a local
  derived from one, in a function the scan can resolve);
* the summary is unseeded, so a pass-through of a parameter is never claimed
  here — callers with real tainted arguments are already covered by the
  caller-side propagation;
* depth one is honoured: a second return hop is *not* followed, and the test
  below says so out loud instead of pretending.
"""

from __future__ import annotations

from pathlib import Path

from redfall.ingestion.ingest import ingest


def _write(root: Path, rel: str, source: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _ingest(tmp_path: Path):
    result = ingest("test-return-flow", tmp_path)
    assert result.parse_errors == []
    return result


def _taints(result):
    return [
        (f.path, t.line, t.sink, t.symbol, t.via)
        for f in result.files
        for t in f.taints
    ]


# ------------------------------------------------------------------ TypeScript
TS_PROVIDER = """\
export function readToken(req: any) {
  return req.headers.authorization;
}
"""

TS_ROUTES = """\
import { readToken } from './provider';

export function handler(pool: any, req: any) {
  const token = readToken(req);
  return pool.query('SELECT * FROM sessions WHERE token = ' + token);
}
"""


def test_ts_helper_that_returns_a_source_taints_the_stored_result(tmp_path):
    _write(tmp_path, "provider.ts", TS_PROVIDER)
    _write(tmp_path, "routes.ts", TS_ROUTES)
    rows = _taints(_ingest(tmp_path))
    assert len(rows) == 1, rows
    path, line, sink, symbol, via = rows[0]
    assert (path, line, sink, symbol) == ("routes.ts", 5, "pool.query", "handler")
    joined = " | ".join(via)
    assert "readToken() returns req.headers -> token" in joined, via


TS_SAFE = """\
export function label() {
  return 'constant';
}

export function handler(pool: any) {
  const name = label();
  return pool.query('SELECT * FROM t WHERE name = ' + name);
}
"""


def test_ts_helper_returning_a_constant_is_not_a_source(tmp_path):
    _write(tmp_path, "app.ts", TS_SAFE)
    assert _taints(_ingest(tmp_path)) == []


TS_INNER = """\
export function inner(req: any) {
  return req.query.q;
}
"""

TS_MID = """\
import { inner } from './inner';

export function mid(req: any) {
  return inner(req);
}
"""

TS_OUTER = """\
import { mid } from './mid';

export function handler(pool: any, req: any) {
  const v = mid(req);
  return pool.query('SELECT ' + v);
}
"""


def test_ts_two_returns_beyond_a_source_are_not_claimed_at_depth_one(tmp_path):
    # mid returns what inner returned; following that would be a second hop.
    # Depth one stops at the boundary and this test documents it.
    _write(tmp_path, "inner.ts", TS_INNER)
    _write(tmp_path, "mid.ts", TS_MID)
    _write(tmp_path, "routes.ts", TS_OUTER)
    assert _taints(_ingest(tmp_path)) == []


TS_ARROW = """\
export const readTerm = (req: any) => req.query.term;

export function handler(pool: any, req: any) {
  const term = readTerm(req);
  return pool.query('SELECT * FROM t WHERE term = ' + term);
}
"""


def test_ts_concise_arrow_body_returns_flow(tmp_path):
    _write(tmp_path, "app.ts", TS_ARROW)
    rows = _taints(_ingest(tmp_path))
    assert len(rows) == 1, rows
    _path, _line, sink, symbol, via = rows[0]
    assert (sink, symbol) == ("pool.query", "handler")
    assert any("readTerm() returns req.query" in v for v in via), via


TS_MODULE_LEVEL = """\
import { readToken } from './provider';

const t = readToken({} as any);
export function unused(pool: any) {
  return pool;
}
"""


def test_ts_module_level_calls_are_not_the_passs_business(tmp_path):
    _write(tmp_path, "provider.ts", TS_PROVIDER)
    _write(tmp_path, "app.ts", TS_MODULE_LEVEL)
    assert _taints(_ingest(tmp_path)) == []


# ---------------------------------------------------------------------- Python
PY_PROVIDER = """\
def read_term(request):
    return request.args.get('term')
"""

PY_ROUTES = """\
from provider import read_term


def handler(cursor, request):
    term = read_term(request)
    return cursor.execute('SELECT * FROM t WHERE term = ' + term)
"""


def test_python_helper_that_returns_a_source_taints_the_stored_result(tmp_path):
    _write(tmp_path, "provider.py", PY_PROVIDER)
    _write(tmp_path, "routes.py", PY_ROUTES)
    rows = _taints(_ingest(tmp_path))
    assert len(rows) == 1, rows
    path, line, sink, symbol, via = rows[0]
    assert (path, line, symbol) == ("routes.py", 6, "handler")
    assert "execute" in sink
    joined = " | ".join(via)
    assert "read_term() returns request.args" in joined, via
    assert "-> term" in joined, via


PY_SAFE = """\
def label():
    return 'constant'


def handler(cursor):
    name = label()
    return cursor.execute('SELECT * FROM t WHERE name = ' + name)
"""


def test_python_helper_returning_a_constant_is_not_a_source(tmp_path):
    _write(tmp_path, "app.py", PY_SAFE)
    assert _taints(_ingest(tmp_path)) == []


PY_INNER = """\
def inner(request):
    return request.query_params.get('q')
"""

PY_MID2 = """\
from inner import inner


def mid(request):
    return inner(request)
"""

PY_OUTER = """\
from mid import mid


def handler(cursor, request):
    v = mid(request)
    return cursor.execute('SELECT ' + v)
"""


def test_python_two_returns_beyond_a_source_are_not_claimed_at_depth_one(tmp_path):
    _write(tmp_path, "inner.py", PY_INNER)
    _write(tmp_path, "mid.py", PY_MID2)
    _write(tmp_path, "routes.py", PY_OUTER)
    assert _taints(_ingest(tmp_path)) == []
