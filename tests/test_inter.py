"""The interprocedural pass: one provable hop, a call graph, no guessing.

Every test builds a small multi-file tree, runs the real `ingest`, and asserts
against what the pass actually resolved. The honest negative cases are as
important as the positive ones: ambiguous imports, missing functions and
parameter chains that never touch a real source must produce nothing.
"""

from __future__ import annotations

from pathlib import Path

from redfall.ingestion.ingest import ingest

ROOT = Path(__file__).resolve().parent.parent

CORE = '''\
"""Reporting helpers."""


def lookup(conn, term):
    query = "SELECT value FROM items WHERE name = '" + term + "'"
    return conn.execute(query).fetchall()
'''

ROUTES = '''\
from flask import Blueprint, request
from .core import lookup

bp = Blueprint("items", __name__, url_prefix="/items")


@bp.get("/search")
def search():
    conn = connect()
    term = request.args.get("q", "")
    rows = lookup(conn, term)
    return {"rows": rows}
'''

SAME_FILE = '''\
from flask import Blueprint, request
import sqlite3

bp = Blueprint("t", __name__)


def fetch(conn, payload):
    return conn.execute(payload).fetchall()


@bp.get("/a")
def via_positional():
    conn = sqlite3.connect(":memory:")
    row = request.args.get("row")
    return fetch(conn, row)


@bp.get("/b")
def via_keyword():
    conn = sqlite3.connect(":memory:")
    row = request.args.get("row")
    return fetch(conn, payload=row)
'''

CLASSY = '''\
from flask import request


class Admin:
    def build(self, name):
        return eval(name)

    def handle(self):
        raw = request.args.get("expr")
        return self.build(raw)
'''

CYCLE = '''\
from flask import request


def a(conn, value):
    return b(conn, value)


def b(conn, value):
    if value:
        return a(conn, value)
    conn.execute(value)


def route():
    q = request.args.get("q")
    return a(conn, q)
'''


def _write(tmp_path: Path, rel: str, source: str) -> None:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _file(result, rel: str):
    return next(f for f in result.files if f.path == rel)


def test_cross_module_hop_lands_on_the_callee_sink(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/core.py", CORE)
    _write(tmp_path, "pkg/routes.py", ROUTES)
    result = ingest("test-inter-cross", tmp_path)

    core = _file(result, "pkg/core.py")
    hops = [t for t in core.taints if t.symbol == "lookup"]
    assert len(hops) == 1, f"expected one interprocedural hit, got {core.taints}"
    hop = hops[0]
    assert hop.sink == "conn.execute" and hop.sink_kind == "db"
    assert hop.line == 6  # the sink call, not the module it was called from
    assert hop.source == "request.args.get()"
    assert hop.via[0] == "request.args.get() -> search (pkg/routes.py:11)"
    assert hop.via[1] == "pkg.core.lookup -> lookup via argument 2 (pkg/core.py)"
    assert hop.via[2] == "param term -> conn.execute"

    edge = next(e for e in result.call_edges if e.callee_function == "lookup")
    assert edge.caller_file == "pkg/routes.py"
    assert edge.caller_function == "search"
    assert edge.callee_file == "pkg/core.py"
    assert edge.tainted_params == ["term"]


def test_ambiguous_module_import_is_not_guessed(tmp_path):
    body = "def run(sql):\n    conn = connect()\n    return conn.execute(sql)\n"
    _write(tmp_path, "a/mod.py", body)
    _write(tmp_path, "b/mod.py", body)
    _write(
        tmp_path,
        "route.py",
        "from mod import run\n"
        "from flask import request\n"
        "\n"
        "\n"
        "def handler():\n"
        "    q = request.args.get('q')\n"
        "    return run(q)\n",
    )
    result = ingest("test-inter-ambiguous", tmp_path)
    assert result.call_edges == []
    assert [t for f in result.files for t in f.taints] == []


def test_missing_callee_is_not_an_edge(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/core.py", "def present(conn, x):\n    return x\n")
    _write(
        tmp_path,
        "pkg/routes.py",
        "from .core import absent\n"
        "from flask import request\n"
        "\n"
        "\n"
        "def handler():\n"
        "    q = request.args.get('q')\n"
        "    return absent(q)\n",
    )
    result = ingest("test-inter-missing", tmp_path)
    assert result.call_edges == []


def test_same_file_helper_hop_covers_positional_and_keyword_args(tmp_path):
    _write(tmp_path, "app.py", SAME_FILE)
    result = ingest("test-inter-same", tmp_path)

    app = _file(result, "app.py")
    hops = [t for t in app.taints if t.symbol == "fetch"]
    assert len(hops) == 1
    assert hops[0].line == 8
    assert hops[0].via[1] == "fetch -> fetch via argument 2 (app.py)"

    edges = [
        (e.caller_function, tuple(e.tainted_params))
        for e in result.call_edges
        if e.callee_function == "fetch"
    ]
    assert edges == [("via_positional", ("payload",)), ("via_keyword", ("payload",))]


def test_self_method_hop(tmp_path):
    _write(tmp_path, "app.py", CLASSY)
    result = ingest("test-inter-method", tmp_path)

    app = _file(result, "app.py")
    hops = [t for t in app.taints if t.symbol == "Admin.build"]
    assert len(hops) == 1
    assert hops[0].sink == "eval" and hops[0].sink_kind == "exec"
    assert hops[0].line == 6
    assert hops[0].via[1] == "self.build -> Admin.build via argument 1 (app.py)"

    edge = next(e for e in result.call_edges if e.callee_function == "Admin.build")
    assert edge.caller_function == "Admin.handle"
    assert edge.tainted_params == ["name"]


def test_depth_one_does_not_walk_cycles(tmp_path):
    _write(tmp_path, "app.py", CYCLE)
    result = ingest("test-inter-cycle", tmp_path)

    # `conn.execute(value)` in b is fed only by a parameter that itself came
    # from `a`'s parameter two calls away from the real source: depth one must
    # not claim it, and mutual recursion must not invent anything or hang.
    assert [t for f in result.files for t in f.taints] == []
    pairs = {(e.caller_function, e.callee_function) for e in result.call_edges}
    assert pairs == {("route", "a"), ("a", "b"), ("b", "a")}


def test_own_codebase_gains_a_call_graph_without_errors():
    result = ingest("test-self-inter", ROOT / "src" / "redfall")
    assert result.parse_errors == []
    assert len(result.call_edges) >= 10, f"only {len(result.call_edges)} edges resolved"

    by_path = {f.path: f for f in result.files}
    for edge in result.call_edges:
        assert edge.callee_file in by_path, f"edge targets unknown file {edge.callee_file}"
        names = {fn.name for fn in by_path[edge.callee_file].symbols.functions}
        assert edge.callee_function in names, f"edge targets unknown function {edge.callee_function}"
