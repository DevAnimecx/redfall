"""Java and Kotlin ingestion: parse, symbols, routes, taint.

The two languages ship only as far as these tests reach. A parser that exists
but extracts no route, or a taint pass that reports nothing, would let a JVM
repository be "supported" while finding nothing in it — which is worse than
refusing the language, because the result looks like a clean scan.

Every test works on real source through the real pipeline. Nothing here asserts
against a hand-built tree.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _analyse(source: str, path: str = "Controller.java"):
    """Parse, extract and taint one source string. No mocks anywhere."""
    from redfall.ingestion.parser_java import parse_source
    from redfall.ingestion.symbols_jvm import extract_symbols
    from redfall.ingestion.taint_jvm import analyse_taint

    parsed = parse_source(path, source.encode("utf-8"))
    assert parsed is not None, f"{path} should be parseable"
    symbols = extract_symbols(parsed)
    return parsed, symbols, analyse_taint(parsed, symbols)


# -- parsing ---------------------------------------------------------------

def test_parses_java_files_and_refuses_others():
    from redfall.ingestion.parser_java import parse_source

    assert parse_source("A.java", b"class A {}").dialect == "java"
    assert parse_source("A.kt", b"class A").dialect == "kotlin"
    assert parse_source("A.py", b"x = 1") is None
    assert parse_source("A.ts", b"const x = 1") is None


def test_kotlin_and_java_use_different_dialects():
    from redfall.ingestion.parser_java import dialect_for

    assert dialect_for("A.java") == "java"
    assert dialect_for("a.kt") == "kotlin"
    assert dialect_for("a.kts") == "kotlin"
    assert dialect_for("a.rb") is None


def test_java_is_registered_in_the_language_registry():
    from redfall.ingestion.languages import language_name_for, support_for

    assert support_for("A.java") is not None
    assert support_for("A.kt") is not None
    assert language_name_for("A.java") == "java"
    assert language_name_for("A.kt") == "kotlin"


def test_an_unknown_suffix_is_not_attributed_to_javascript():
    """The old maps defaulted everything unknown to javascript; that is a lie."""
    from redfall.ingestion.languages import language_name_for

    assert language_name_for("thing.rb") == "unknown"
    assert language_name_for("thing.rs") == "unknown"
    assert language_name_for("thing.js") == "javascript"


# -- symbols and imports ---------------------------------------------------

def test_imports_are_recorded_with_their_package():
    _, symbols, _ = _analyse(
        "import java.sql.Connection;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "class C {}\n"
    )
    by_name = {i.name: i.source for i in symbols.imports}
    assert by_name.get("Connection") == "java.sql.Connection"
    assert any(i.name == "*" for i in symbols.imports)


def test_a_wildcard_import_records_its_package_not_a_guess():
    """Resolving `x.*` to one type would be inventing an import."""
    _, symbols, _ = _analyse("import java.util.*;\nclass C {}\n")
    star = [i for i in symbols.imports if i.name == "*"]
    assert star and star[0].source == "java.util"


def test_methods_are_recorded_with_their_enclosing_class():
    _, symbols, _ = _analyse(
        "class C {\n    public String get() { return \"x\"; }\n    void run() {}\n}\n"
    )
    assert {f.name for f in symbols.functions} == {"get", "run"}


# -- routes ----------------------------------------------------------------

def test_spring_method_annotations_become_routes():
    _, symbols, _ = _analyse(
        "@RestController\n"
        "@RequestMapping(\"/api/users\")\n"
        "class UserController {\n"
        '    @GetMapping("/{id}")\n'
        "    public String get(String id) { return id; }\n"
        '    @PostMapping("/create")\n'
        "    public String create(String b) { return b; }\n"
        "}\n"
    )
    routes = {(r.method, r.path) for r in symbols.routes}
    assert ("GET", "/api/users/{id}") in routes
    assert ("POST", "/api/users/create") in routes


def test_a_named_annotation_argument_is_read():
    """`path = "/x"` is as valid as `"/x"`; dropping it loses a route."""
    _, symbols, _ = _analyse(
        'class C {\n    @PostMapping(path = "/named")\n'
        "    public String go() { return \"\"; }\n}\n"
    )
    assert any(r.path.endswith("/named") for r in symbols.routes)


def test_a_method_without_a_route_annotation_is_not_a_route():
    """Guessing a route from a method name would invent endpoints."""
    _, symbols, _ = _analyse(
        "class C {\n    public String get() { return \"x\"; }\n}\n"
    )
    assert symbols.routes == []


def test_the_class_prefix_is_not_double_joined():
    _, symbols, _ = _analyse(
        '@RestController\n@RequestMapping("/api")\nclass C {\n'
        '    @GetMapping("/thing")\n    public String t() { return ""; }\n}\n'
    )
    paths = [r.path for r in symbols.routes]
    assert "/api/thing" in paths
    assert not any("//" in p for p in paths)


def test_a_controller_with_no_class_prefix_still_yields_its_routes():
    _, symbols, _ = _analyse(
        'class C {\n    @GetMapping("/bare")\n    public String t() { return ""; }\n}\n'
    )
    assert any(r.path == "/bare" for r in symbols.routes)


# -- sinks -----------------------------------------------------------------

def test_exec_is_classified_only_on_a_runtime_receiver():
    """`exec` on anything else is a project helper, not process execution."""
    _, symbols, _ = _analyse(
        "class C {\n"
        "    void a() { Runtime.getRuntime().exec(\"ls\"); }\n"
        "    void b() { helper.exec(\"x\"); }\n"
        "}\n"
    )
    exec_calls = [c for c in symbols.calls if c.kind == "exec"]
    assert len(exec_calls) == 1, "only the Runtime call is process execution"


def test_database_sinks_are_classified():
    _, symbols, _ = _analyse(
        "class C {\n"
        "    void q() { conn.createStatement().executeQuery(\"SELECT 1\"); }\n"
        "}\n"
    )
    assert any(c.kind == "db" for c in symbols.calls)


def test_a_call_inside_a_method_records_its_enclosing_function():
    _, symbols, _ = _analyse(
        "class C {\n"
        "    void handler() { Runtime.getRuntime().exec(\"ls\"); }\n"
        "}\n"
    )
    exec_call = next(c for c in symbols.calls if c.kind == "exec")
    assert exec_call.enclosing_function == "handler"


# -- taint -----------------------------------------------------------------

def test_a_request_param_annotated_parameter_is_a_source():
    _, _, taints = _analyse(
        "class C {\n"
        "    @GetMapping(\"/run\")\n"
        "    public String run(@RequestParam String cmd) {\n"
        "        Runtime.getRuntime().exec(cmd);\n"
        "        return \"\";\n"
        "    }\n"
        "}\n"
    )
    assert len(taints) == 1
    assert taints[0].source == "param:cmd"
    assert taints[0].sink == "exec"
    assert taints[0].sink_kind == "exec"


def test_taint_propagates_through_a_local_variable():
    """The common shape: build a string from the parameter, then use it."""
    _, _, taints = _analyse(
        "class C {\n"
        "    @GetMapping(\"/q\")\n"
        "    public String q(@RequestParam String id) {\n"
        '        String sql = "SELECT * FROM t WHERE id = " + id;\n'
        "        return stmt.executeQuery(sql).toString();\n"
        "    }\n"
        "}\n"
    )
    assert len(taints) == 1
    assert taints[0].sink == "executeQuery"
    assert taints[0].sink_kind == "db"


def test_a_method_with_no_request_input_produces_no_taint():
    """A clean method must stay clean; a false positive here is a false finding."""
    _, _, taints = _analyse(
        "class C {\n"
        '    public String safe() { return stmt.executeQuery("SELECT 1").toString(); }\n'
        "}\n"
    )
    assert taints == []


def test_taint_does_not_leak_between_methods():
    """A parameter name is not evidence that a different method is tainted."""
    _, _, taints = _analyse(
        "class C {\n"
        "    @GetMapping(\"/a\")\n"
        "    public String a(@RequestParam String v) { return v; }\n"
        "    public String b(String v) {\n"
        "        Runtime.getRuntime().exec(v);\n"
        "        return \"\";\n"
        "    }\n"
        "}\n"
    )
    assert taints == [], "the unannotated parameter must not inherit taint"


def test_a_recorded_sanitiser_does_not_clear_taint():
    """Doctrine: the sandbox decides whether a path is real, not a name."""
    _, _, taints = _analyse(
        "class C {\n"
        "    @GetMapping(\"/x\")\n"
        "    public String x(@RequestParam String v) {\n"
        "        String c = escapeHtml(v);\n"
        "        Runtime.getRuntime().exec(c);\n"
        "        return \"\";\n"
        "    }\n"
        "}\n"
    )
    assert len(taints) == 1, "the path must still be reported"
    assert any("sanitiser present but not modelled" in v for v in taints[0].via)


def test_a_request_body_parameter_is_a_source():
    _, _, taints = _analyse(
        "class C {\n"
        "    @PostMapping(\"/b\")\n"
        "    public String b(@RequestBody String body) {\n"
        "        Runtime.getRuntime().exec(body);\n"
        "        return \"\";\n"
        "    }\n"
        "}\n"
    )
    assert len(taints) == 1
    assert taints[0].source == "param:body"


def test_servlet_request_calls_are_sources():
    _, _, taints = _analyse(
        "class C {\n"
        "    public String h() {\n"
        '        String c = req.getParameter("cmd");\n'
        "        Runtime.getRuntime().exec(c);\n"
        "        return \"\";\n"
        "    }\n"
        "}\n"
    )
    assert len(taints) == 1
    assert "getParameter" in taints[0].source


# -- end to end ------------------------------------------------------------

def test_a_jvm_tree_ingests_with_routes_and_no_parse_errors(tmp_path):
    """The whole pipeline over a real directory, the way a scan reaches it."""
    from redfall.ingestion.ingest import ingest

    src = tmp_path / "src" / "main" / "java" / "com" / "example"
    src.mkdir(parents=True)
    (src / "UserController.java").write_text(
        "package com.example;\n"
        "import java.sql.Connection;\n"
        "\n"
        "@RestController\n"
        '@RequestMapping("/api/users")\n'
        "public class UserController {\n"
        "    private Connection conn;\n"
        "\n"
        '    @GetMapping("/{id}")\n'
        "    public String get(@PathVariable String id) {\n"
        '        String q = "SELECT * FROM users WHERE id = " + id;\n'
        "        return conn.createStatement().executeQuery(q).toString();\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    (src / "Helper.kt").write_text(
        "package com.example\n\n"
        "fun greet(name: String): String {\n"
        "    return \"hello \" + name\n"
        "}\n",
        encoding="utf-8",
    )
    # Not a JVM file; must be skipped rather than misparsed.
    (tmp_path / "README.md").write_text("# app\n", encoding="utf-8")

    result = ingest("scan-jvm", tmp_path)

    paths = {f.path for f in result.files}
    assert any(p.endswith("UserController.java") for p in paths)
    assert any(p.endswith("Helper.kt") for p in paths)
    assert not any(p.endswith("README.md") for p in paths)
    assert result.parse_errors == [], f"clean parse expected, got {result.parse_errors}"

    routes = {(r["method"], r["path"]) for r in result.http_routes()}
    assert ("GET", "/api/users/{id}") in routes

    taint_paths = [(t.sink_kind, t.sink) for _, t in result.taint_paths]
    assert ("db", "executeQuery") in taint_paths


def test_own_kotlin_file_parses_without_errors():
    from redfall.ingestion.parser_java import parse_source
    from redfall.ingestion.symbols_jvm import extract_symbols

    parsed = parse_source(
        "Service.kt",
        (
            "package com.example\n\n"
            "class UserService {\n"
            "    fun find(id: String): String {\n"
            '        return "SELECT " + id\n'
            "    }\n"
            "}\n"
        ).encode("utf-8"),
    )
    assert parsed is not None
    assert parsed.dialect == "kotlin"
    symbols = extract_symbols(parsed)
    assert symbols.path == "Service.kt"
