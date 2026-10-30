"""Go ingestion: parse, symbols, routes, taint.

Go ships only as far as these tests reach. Getting the import binding wrong —
recording `net/http` as the name instead of `http` — would silently break every
sink resolution in the language while still looking like it worked, so that
behaviour is pinned explicitly.

Every test runs real source through the real pipeline.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _analyse(source: str, path: str = "main.go"):
    from redfall.ingestion.parser_go import parse_source
    from redfall.ingestion.symbols_go import extract_symbols
    from redfall.ingestion.taint_go import analyse_taint

    parsed = parse_source(path, source.encode("utf-8"))
    assert parsed is not None, f"{path} should be parseable"
    symbols = extract_symbols(parsed)
    return parsed, symbols, analyse_taint(parsed, symbols)


# -- parsing ---------------------------------------------------------------

def test_parses_go_files_and_refuses_others():
    from redfall.ingestion.parser_go import parse_source

    parsed = parse_source("main.go", b"package main\n")
    assert parsed is not None
    assert parsed.dialect == "go"
    assert parse_source("main.py", b"x = 1") is None
    assert parse_source("Main.java", b"class A {}") is None


def test_go_is_registered_in_the_language_registry():
    from redfall.ingestion.languages import language_name_for, support_for

    assert support_for("main.go") is not None
    assert language_name_for("main.go") == "go"


# -- imports ---------------------------------------------------------------

def test_an_import_binds_its_last_path_segment():
    """`net/http` is used as `http`; recording the whole path breaks every sink."""
    _, symbols, _ = _analyse(
        'package main\nimport (\n\t"net/http"\n\t"os/exec"\n)\n'
    )
    by_source = {i.source: i.name for i in symbols.imports}
    assert by_source["net/http"] == "http"
    assert by_source["os/exec"] == "exec"


def test_a_single_import_declaration_is_read():
    _, symbols, _ = _analyse('package main\nimport "database/sql"\n')
    assert any(i.name == "sql" and i.source == "database/sql" for i in symbols.imports)


def test_an_aliased_import_records_the_alias():
    _, symbols, _ = _analyse('package main\nimport h "net/http"\n')
    alias = [i for i in symbols.imports if i.name == "h"]
    assert alias and alias[0].source == "net/http"


# -- functions -------------------------------------------------------------

def test_functions_are_recorded():
    _, symbols, _ = _analyse(
        "package main\nfunc handler() {}\nfunc Helper() {}\n"
    )
    assert {f.name for f in symbols.functions} == {"handler", "Helper"}


def test_exportedness_follows_the_capital():
    _, symbols, _ = _analyse("package main\nfunc Exported() {}\nfunc hidden() {}\n")
    by_name = {f.name: f.is_exported for f in symbols.functions}
    assert by_name["Exported"] is True
    assert by_name["hidden"] is False


# -- routes ----------------------------------------------------------------

def test_net_http_handlefunc_is_a_route():
    _, symbols, _ = _analyse(
        'package main\nimport "net/http"\n'
        'func main() { http.HandleFunc("/users", handler) }\n'
    )
    assert any(r.path == "/users" and r.handler == "handler" for r in symbols.routes)


def test_gin_style_method_registration_is_a_route():
    _, symbols, _ = _analyse(
        "package main\n"
        "func main() {\n"
        '    r := gin.Default()\n'
        '    r.GET("/items/:id", getItem)\n'
        '    r.POST("/items", create)\n'
        "}\n"
    )
    routes = {(r.method, r.path) for r in symbols.routes}
    assert ("GET", "/items/:id") in routes
    assert ("POST", "/items") in routes


def test_a_route_with_a_variable_path_is_not_guessed():
    """A path that is not readable here must not become an invented one."""
    _, symbols, _ = _analyse(
        "package main\n"
        "func main() {\n"
        "    p := computePath()\n"
        "    r.GET(p, handler)\n"
        "}\n"
    )
    assert symbols.routes == []


def test_a_router_group_records_a_mount():
    _, symbols, _ = _analyse(
        "package main\n"
        "func main() {\n"
        '    api := r.Group("/api")\n'
        '    api.GET("/users", list)\n'
        "}\n"
    )
    assert any(m.prefix == "/api" and m.local_name == "api" for m in symbols.mounts)


# -- sinks -----------------------------------------------------------------

def test_exec_command_is_a_sink_only_with_the_exec_package():
    """`Command` on a project's own type is not process execution."""
    _, symbols, _ = _analyse(
        "package main\nimport \"os/exec\"\n"
        "func a() { exec.Command(\"ls\") }\n"
        "func b() { runner.Command(\"ls\") }\n"
    )
    exec_calls = [c for c in symbols.calls if c.kind == "exec"]
    assert len(exec_calls) == 1


def test_database_calls_on_a_db_receiver_are_sinks():
    _, symbols, _ = _analyse(
        'package main\nfunc q() { db.Query("SELECT 1") }\n'
    )
    assert any(c.kind == "db" for c in symbols.calls)


def test_an_ambiguous_get_is_not_assumed_to_be_a_request():
    """`Get` on a cache is a lookup; calling it SSRF would invent a finding."""
    _, symbols, _ = _analyse(
        "package main\nfunc f() { cache.Get(\"key\") }\n"
    )
    assert not any(c.kind == "fetch" for c in symbols.calls)


# -- taint -----------------------------------------------------------------

def test_a_request_parameter_makes_the_handler_tainted():
    _, _, taints = _analyse(
        "package main\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n"
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        '    cmd := r.URL.Query().Get("cmd")\n'
        '    exec.Command("sh", "-c", cmd)\n'
        "}\n"
    )
    assert len(taints) == 1
    assert taints[0].sink == "Command"
    assert taints[0].sink_kind == "exec"


def test_a_request_parameter_is_a_source_even_without_a_query_call():
    _, _, taints = _analyse(
        "package main\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n"
        "func handler(r *http.Request) {\n"
        '    exec.Command("sh", "-c", r.FormValue("x"))\n'
        "}\n"
    )
    assert len(taints) == 1


def test_a_function_with_no_request_input_produces_no_taint():
    _, _, taints = _analyse(
        "package main\nimport \"os/exec\"\n"
        'func safe() { exec.Command("ls") }\n'
    )
    assert taints == []


def test_taint_does_not_leak_between_functions():
    _, _, taints = _analyse(
        "package main\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n"
        "func source(r *http.Request) { _ = r.FormValue(\"x\") }\n"
        "func sink(v string) { exec.Command(\"sh\", \"-c\", v) }\n"
    )
    assert taints == [], "an untainted parameter must not inherit a neighbour's taint"


def test_a_recorded_sanitiser_does_not_clear_taint():
    _, _, taints = _analyse(
        "package main\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n"
        "func handler(r *http.Request) {\n"
        '    v := html.EscapeString(r.FormValue("x"))\n'
        '    exec.Command("sh", "-c", v)\n'
        "}\n"
    )
    assert len(taints) == 1, "the path must still be reported"
    assert any("sanitiser present but not modelled" in v for v in taints[0].via)


# -- end to end ------------------------------------------------------------

def test_a_go_tree_ingests_with_routes_and_no_parse_errors(tmp_path):
    from redfall.ingestion.ingest import ingest

    svc = tmp_path / "cmd" / "server"
    svc.mkdir(parents=True)
    (svc / "main.go").write_text(
        "package main\n"
        "\n"
        "import (\n"
        '\t"net/http"\n'
        '\t"os/exec"\n'
        ")\n"
        "\n"
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        '\tcmd := r.URL.Query().Get("cmd")\n'
        '\tout, _ := exec.Command("sh", "-c", cmd).Output()\n'
        "\tw.Write(out)\n"
        "}\n"
        "\n"
        "func main() {\n"
        '\thttp.HandleFunc("/run", handler)\n'
        "\thttp.ListenAndServe(\":8080\", nil)\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "notes.txt").write_text("not source\n", encoding="utf-8")

    result = ingest("scan-go", tmp_path)

    paths = {f.path for f in result.files}
    assert any(p.endswith("main.go") for p in paths)
    assert not any(p.endswith("notes.txt") for p in paths)
    assert result.parse_errors == [], f"clean parse expected, got {result.parse_errors}"

    routes = {(r["method"], r["path"]) for r in result.http_routes()}
    assert ("ANY", "/run") in routes

    taint_paths = [(t.sink_kind, t.sink) for _, t in result.taint_paths]
    assert ("exec", "Command") in taint_paths
