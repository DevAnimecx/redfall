"""The Python engine: real parsing, real symbol extraction, real taint.

No fixtures beyond source strings and a temp file: every assertion is made
against a tree that tree-sitter actually produced, and the last test runs the
whole pipeline over Redfall's own Python codebase.
"""

from __future__ import annotations

from pathlib import Path

from redfall.ingestion.ingest import ingest
from redfall.ingestion.parser_py import parse_source
from redfall.ingestion.symbols_py import classify_call, extract_symbols, resolve_dotted
from redfall.ingestion.taint_py import analyse_taint

ROOT = Path(__file__).resolve().parent.parent

WEB_APP = """\
import os, pickle
from flask import Blueprint, Flask, request
from fastapi import APIRouter, FastAPI
from subprocess import run as run_cmd
from django.urls import path, re_path

bp = Blueprint("users", __name__, url_prefix="/api/users")
app = FastAPI()
api = APIRouter(prefix="/v1")
legacy = Flask(__name__)


@bp.route("/login", methods=["POST"])
def login():
    q = request.form["username"]
    cur.execute("SELECT * FROM users WHERE name = '" + q + "'")
    os.system("echo " + q)


@bp.get("/<int:uid>")
def get_user(uid):
    data = request.args.get("x") or request.json["payload"]
    name = data["name"]
    return pickle.loads(name)


@bp.route("/multi", methods=["GET", "POST"])
def multi():
    return "ok"


@api.get("/items")
def items():
    return []


@legacy.post("/hook")
def hook():
    return "ok"


@bp.route("/run")
def run_it():
    cmd = request.args.get("cmd", "")
    run_cmd(cmd, shell=True)


urlpatterns = [
    path("items/<int:pk>/", views.item),
    re_path(r"^legacy/", views.legacy),
]


def _hidden():
    return 1


class Thing:
    def method(self):
        z = request.args.get("z")
        with open(os.path.join("/tmp", z)) as fh:
            return pickle.load(fh)


def never_touched():
    a = request.args.get("a")
    return a


def uses_the_same_name():
    return eval(a)
"""


def _analyse(tmp_path: Path, source: str):
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    parsed = parse_source(path)
    assert parsed is not None
    symbols = extract_symbols(parsed)
    return symbols, analyse_taint(parsed, symbols)


def test_parses_python_files_and_refuses_others(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("x = 1\n", encoding="utf-8")
    assert parse_source(path).dialect == "python"
    other = tmp_path / "app.rb"
    other.write_text("x = 1\n", encoding="utf-8")
    assert parse_source(other) is None


def test_flask_routes_carry_their_blueprint_prefix(tmp_path):
    symbols, _ = _analyse(tmp_path, WEB_APP)
    routes = {(r.method, r.path) for r in symbols.routes}
    assert ("POST", "/api/users/login") in routes
    assert ("GET", "/api/users/<int:uid>") in routes
    assert ("GET/POST", "/api/users/multi") in routes
    assert ("GET", "/api/users/run") in routes
    assert ("POST", "/hook") in routes  # a Flask app with no prefix stays unprefixed


def test_fastapi_router_prefix_is_applied(tmp_path):
    symbols, _ = _analyse(tmp_path, WEB_APP)
    routes = {(r.method, r.path) for r in symbols.routes}
    assert ("GET", "/v1/items") in routes


def test_django_urlpatterns_are_routes(tmp_path):
    symbols, _ = _analyse(tmp_path, WEB_APP)
    django = [r for r in symbols.routes if r.receiver == "django"]
    assert [(r.method, r.path, r.handler) for r in django] == [
        ("ANY", "items/<int:pk>/", "views.item"),
        ("ANY", "^legacy/", "views.legacy"),
    ]


def test_django_path_outside_urlpatterns_is_not_guessed(tmp_path):
    symbols, _ = _analyse(
        tmp_path,
        "def f():\n    return path('x/', view)\n",
    )
    assert symbols.routes == []


def test_functions_and_methods_are_named(tmp_path):
    symbols, _ = _analyse(tmp_path, WEB_APP)
    names = {f.name for f in symbols.functions}
    assert {"login", "get_user", "items", "hook", "Thing.method", "never_touched"} <= names
    hidden = next(f for f in symbols.functions if f.name == "_hidden")
    assert hidden.is_exported is False


def test_import_aliases_resolve_to_real_names(tmp_path):
    symbols, _ = _analyse(tmp_path, WEB_APP)
    aliases = {i.name: (i.source, i.origin) for i in symbols.imports}
    assert aliases["run_cmd"] == ("subprocess", "run")
    assert aliases["request"] == ("flask", "request")
    assert resolve_dotted("run_cmd", {k: f"{s}.{o}" if o else s for k, (s, o) in aliases.items()}) == "subprocess.run"


def test_sink_classification_vocabulary():
    assert classify_call("subprocess.run") == ("exec", "subprocess.run")
    assert classify_call("eval") == ("exec", "eval")
    assert classify_call("pickle.loads") == ("exec", "pickle.loads")
    assert classify_call("yaml.load") == ("exec", "yaml.load")
    assert classify_call("yaml.safe_load") is None
    assert classify_call("session.execute") == ("db", "session.execute")
    assert classify_call("shutil.rmtree") == ("fs", "shutil.rmtree")
    assert classify_call("os.path.join") == ("fs", "os.path.join")
    assert classify_call("requests.post") == ("fetch", "requests.post")
    assert classify_call("print") is None


def test_taint_propagates_into_sql_and_shell_sinks(tmp_path):
    symbols, taints = _analyse(tmp_path, WEB_APP)
    hits = {t.sink: t for t in taints if t.symbol == "login"}
    assert hits["cur.execute"].sink_kind == "db"
    assert hits["cur.execute"].source == "request.form"
    assert hits["os.system"].sink_kind == "exec"
    assert "request.form -> q" in hits["os.system"].via[0]


def test_taint_resolves_import_aliases_at_the_sink(tmp_path):
    _, taints = _analyse(tmp_path, WEB_APP)
    hits = [t for t in taints if t.sink == "subprocess.run" and t.symbol == "run_it"]
    assert hits, "aliased subprocess.run was not treated as an exec sink"
    assert hits[0].source == "request.args.get()"


def test_taint_flows_through_subscripts_and_with_bindings(tmp_path):
    _, taints = _analyse(tmp_path, WEB_APP)
    pickle_hits = [t for t in taints if t.sink == "pickle.loads" and t.symbol == "get_user"]
    assert pickle_hits, "request.json -> data -> name -> pickle.loads was not traced"
    with_hits = [t for t in taints if t.sink == "pickle.load" and t.symbol == "Thing.method"]
    assert with_hits, "the with-as binding did not carry taint into pickle.load"


def test_taint_does_not_leak_across_functions(tmp_path):
    _, taints = _analyse(tmp_path, WEB_APP)
    # `uses_the_same_name` calls eval with an `a` that only `never_touched` ever
    # bound; per-function scoping must not connect them.
    assert not [t for t in taints if t.symbol == "uses_the_same_name"]


def test_flask_get_json_is_a_source(tmp_path):
    source = (
        "from flask import request\n"
        "import pickle\n"
        "\n"
        "\n"
        "def load():\n"
        "    payload = request.get_json(silent=True).get('payload')\n"
        "    return pickle.loads(payload)\n"
    )
    _, taints = _analyse(tmp_path, source)
    hits = [t for t in taints if t.sink == "pickle.loads"]
    assert hits, "request.get_json -> payload -> pickle.loads was not traced"
    assert hits[0].sink_kind == "exec"
    assert hits[0].source.startswith("request.get_json")


def test_null_defaults_still_taint_the_variable(tmp_path):
    _, taints = _analyse(tmp_path, WEB_APP)
    upload_like = [
        t
        for t in taints
        if t.sink == "subprocess.run" and t.symbol == "run_it" and t.source == "request.args.get()"
    ]
    assert upload_like, "request.args.get() with a default value must still be a source"


def test_own_python_codebase_ingests_without_errors():
    result = ingest("test-self-python", ROOT / "src" / "redfall")
    python_files = [f for f in result.files if f.path.endswith(".py")]
    mjs_files = [f for f in result.files if f.path.endswith(".mjs")]
    assert len(python_files) >= 40, f"only {len(python_files)} python files parsed"
    assert len(mjs_files) >= 2, "the .mjs harness files must still be picked up"
    assert result.parse_errors == []
    functions = {fn.name for f in result.files for fn in f.symbols.functions}
    assert {"ingest", "extract_symbols", "analyse_taint", "support_for"} <= functions


def test_python_build_directories_are_not_attack_surface(tmp_path):
    for junk in (".venv", "venv", "__pycache__", ".tox", "site-packages"):
        (tmp_path / junk).mkdir()
        (tmp_path / junk / "leftover.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("y = 2\n", encoding="utf-8")
    result = ingest("test-python-skips", tmp_path)
    assert [f.path for f in result.files] == ["app.py"]
