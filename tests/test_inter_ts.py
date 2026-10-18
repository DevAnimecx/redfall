"""The TypeScript interprocedural pass: proven hops, a call graph, no guessing.

Every test builds a small multi-file tree, runs the real `ingest`, and asserts
against what the pass actually resolved. The last test measures the real
`vulnbank` target through the shared session fixture.
"""

from __future__ import annotations

from pathlib import Path

from redfall.ingestion.ingest import ingest

ROOT = Path(__file__).resolve().parent.parent

CORE = """\
export function lookup(pool: any, term: string) {
  const query = "SELECT value FROM items WHERE name = '" + term + "'";
  return pool.query(query);
}
"""

ROUTES = """\
import express from 'express';
import { lookup } from './core';

const app = express();

export function searchHandler(req: any, res: any) {
  const term = req.query.term;
  return lookup(pool, term);
}

app.get('/api/search', searchHandler);
"""

NS_ALIAS_CORE = """\
export function run(cmd: string) {
  return execSync(cmd);
}
"""

NS_ALIAS_ROUTES = """\
import * as core from './core';
import { run as fire } from './core';

export function viaNs(req: any) {
  const cmd = req.body.cmd;
  return core.run(cmd);
}

export function viaAlias(req: any) {
  const cmd = req.body.cmd;
  return fire(cmd);
}
"""

REQUIRE_CORE = """\
function readIt(target) {
  return readFileSync(target);
}

module.exports = { readIt };
"""

REQUIRE_ROUTES = """\
const core = require('./core');
const { readIt } = require('./core');

function viaNs(req) {
  const p = req.query.path;
  return core.readIt(p);
}

function viaDestructured(req) {
  const p = req.query.path;
  return readIt(p);
}
"""

ARROW_CORE = """\
export const save = (db: any, payload: string) => {
  return db.query(payload);
};
"""

ARROW_ROUTES = """\
import { save } from './core';

export function viaPos(req: any) {
  const body = req.body;
  return save(db, body);
}
"""

CYCLE = """\
export function a(pool: any, value: string) {
  return b(pool, value);
}

export function b(pool: any, value: string) {
  if (value) {
    return a(pool, value);
  }
  return pool.query(value);
}

export function route(req: any) {
  const q = req.query.q;
  return a(pool, q);
}
"""


def _write(tmp_path: Path, rel: str, source: str) -> None:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _file(result, rel: str):
    return next(f for f in result.files if f.path == rel)


def test_cross_file_esm_hop_and_route_reachability(tmp_path):
    _write(tmp_path, "core.ts", CORE)
    _write(tmp_path, "routes.ts", ROUTES)
    result = ingest("test-inter-ts-cross", tmp_path)
    assert result.parse_errors == []

    core = _file(result, "core.ts")
    hops = [t for t in core.taints if t.symbol == "lookup"]
    assert len(hops) == 1, f"expected one interprocedural hit, got {core.taints}"
    hop = hops[0]
    assert hop.sink == "pool.query" and hop.sink_kind == "db"
    assert hop.line == 3  # the sink call, in the callee file
    assert hop.source == "req.query"
    assert hop.via[0] == "req.query -> searchHandler (routes.ts:8)"
    assert hop.via[1] == "lookup -> lookup via argument 2 (core.ts)"
    assert hop.via[2] == "param term -> pool.query"

    edge = next(e for e in result.call_edges if e.callee_function == "lookup")
    assert edge.caller_file == "routes.ts"
    assert edge.caller_function == "searchHandler"
    assert edge.callee_file == "core.ts"
    assert edge.tainted_params == ["term"]

    # The route in routes.ts must own the taint in core.ts through the call
    # graph: the handler is what feeds the helper.
    owners = result.routes_for_line("core.ts", hop.line)
    assert [o["path"] for o in owners] == ["/api/search"]
    assert owners[0]["file"] == "routes.ts"


def test_namespace_and_aliased_imports_resolve(tmp_path):
    _write(tmp_path, "core.ts", NS_ALIAS_CORE)
    _write(tmp_path, "routes.ts", NS_ALIAS_ROUTES)
    result = ingest("test-inter-ts-ns", tmp_path)

    core = _file(result, "core.ts")
    hops = [t for t in core.taints if t.symbol == "run"]
    assert len(hops) == 1
    assert hops[0].sink == "execSync" and hops[0].sink_kind == "exec"
    assert hops[0].sink == "execSync" and hops[0].line == 2
    assert hops[0].via[1] == "core.run -> run via argument 1 (core.ts)"

    edges = [(e.caller_function, tuple(e.tainted_params)) for e in result.call_edges]
    assert edges == [("viaNs", ("cmd",)), ("viaAlias", ("cmd",))]


def test_require_bindings_resolve_namespaces_and_destructuring(tmp_path):
    _write(tmp_path, "core.js", REQUIRE_CORE)
    _write(tmp_path, "routes.js", REQUIRE_ROUTES)
    result = ingest("test-inter-ts-require", tmp_path)

    core = _file(result, "core.js")
    hops = [t for t in core.taints if t.symbol == "readIt"]
    assert len(hops) == 1
    assert hops[0].sink == "readFileSync" and hops[0].sink_kind == "fs"
    assert hops[0].via[1] == "core.readIt -> readIt via argument 1 (core.js)"

    edges = [(e.caller_function, tuple(e.tainted_params)) for e in result.call_edges]
    assert edges == [("viaNs", ("target",)), ("viaDestructured", ("target",))]


def test_unresolvable_imports_add_no_edge_and_no_taint(tmp_path):
    _write(tmp_path, "other.ts", "export function present(x: string) {\n  return x;\n}\n")
    _write(
        tmp_path,
        "routes.ts",
        "import { absent } from './other';\n"
        "import { run } from 'mod';\n"
        "\n"
        "export function handler(req: any) {\n"
        "  const q = req.query.q;\n"
        "  absent(q);\n"
        "  run(q);\n"
        "}\n",
    )
    result = ingest("test-inter-ts-unresolved", tmp_path)
    assert result.call_edges == []
    assert [t for f in result.files for t in f.taints] == []


def test_arrow_function_parameters_are_matched_by_position(tmp_path):
    _write(tmp_path, "core.ts", ARROW_CORE)
    _write(tmp_path, "routes.ts", ARROW_ROUTES)
    result = ingest("test-inter-ts-arrow", tmp_path)

    core = _file(result, "core.ts")
    hops = [t for t in core.taints if t.symbol == "save"]
    assert len(hops) == 1
    assert hops[0].line == 2
    assert hops[0].via[1] == "save -> save via argument 2 (core.ts)"

    edge = next(e for e in result.call_edges if e.callee_function == "save")
    assert edge.tainted_params == ["payload"]


def test_depth_one_does_not_walk_cycles(tmp_path):
    _write(tmp_path, "app.ts", CYCLE)
    result = ingest("test-inter-ts-cycle", tmp_path)

    # pool.query(value) in b is fed only by a parameter two calls away from the
    # real source: depth one must not claim it, and mutual recursion must not
    # invent anything or hang.
    assert [t for f in result.files for t in f.taints] == []
    pairs = {(e.caller_function, e.callee_function) for e in result.call_edges}
    assert pairs == {("route", "a"), ("a", "b"), ("b", "a")}


def test_vulnbank_call_graph_is_real(ingest_result):
    """Measured against the real target: cross-file edges with tainted params,
    and no interprocedural claim that a route cannot reach."""
    assert ingest_result.parse_errors == []
    edges = {
        (e.caller_file, e.caller_function, e.callee_file, e.callee_function): e
        for e in ingest_result.call_edges
    }
    login_to_hash = edges[("src/routes/auth.ts", "loginHandler", "src/auth/hash.ts", "verifyPassword")]
    assert login_to_hash.tainted_params == ["plain"]
    assert ("src/middleware/jwt.ts", "requireAuth", "src/middleware/jwt.ts", "verifyToken") in edges
    assert ("src/db/seed.ts", "seed", "src/db/schema.ts", "ensureSchema") in edges
    assert len(ingest_result.call_edges) >= 8

    inter = [(rel, t) for rel, t in ingest_result.taint_paths if t.via and t.via[-1].startswith("param ")]
    for rel, taint in inter:
        assert ingest_result.routes_for_line(rel, taint.line), (
            f"interprocedural taint {rel}:{taint.line} has no reachable route"
        )
