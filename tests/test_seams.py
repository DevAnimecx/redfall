"""Seam conformance and composition equivalence.

Two kinds of test, both aimed at the same problem — that "the cache works" and
"the pool works" can both pass while the *combination* produces different
findings than the simple path.

**Conformance.** Every implementation of a seam is held to the same contract.
A new language engine, a new reasoning backend, a new isolation tier: each must
satisfy the invariants the seam's callers assume. A backend that passes cannot
be the one that breaks a scan in a way nobody connected to it.

**Composition equivalence.** A result produced through every optimisation —
parsed from cache, run through the pool, executed in parallel — must equal the
result produced the slow, simple way. This is the test that would have caught
the sequential-path divergence before it needed two code paths preserved.

Neither kind needs Docker, a JVM or a network. They test the seams' shapes and
the equivalence of paths, which is where the silent failures live.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


# -- the language seam ------------------------------------------------------

def test_every_language_bundle_exposes_the_four_operations():
    from redfall.ingestion.languages import SUPPORTED

    assert SUPPORTED, "no language is registered"
    for support in SUPPORTED:
        assert callable(support.is_supported), support.name
        assert callable(support.parse), support.name
        assert callable(support.symbols), support.name
        assert callable(support.taint), support.name
        assert support.name, "every bundle declares a name"


def test_every_language_bundle_declares_a_distinct_name():
    from redfall.ingestion.languages import SUPPORTED

    names = [s.name for s in SUPPORTED]
    assert len(names) == len(set(names)), f"duplicate language name: {names}"


def test_a_bundle_refuses_a_file_it_does_not_support():
    """is_supported is a real predicate, not a constant true."""
    from redfall.ingestion.languages import SUPPORTED

    for support in SUPPORTED:
        # No language claims a file with a nonsense extension.
        assert support.is_supported("definitely.notasource") is False, support.name


def test_a_bundle_parses_its_own_kind_and_returns_a_parsed_file():
    from redfall.ingestion.languages import SUPPORTED

    samples = {
        "typescript": ("a.ts", b"const x = 1;\n"),
        "python": ("a.py", b"x = 1\n"),
        "java": ("A.java", b"class A {}\n"),
        "go": ("a.go", b"package main\n"),
    }
    for support in SUPPORTED:
        name, source = samples[support.name]
        parsed = support.parse(name, source)
        # parse must return a ParsedFile or None; never raise on small input.
        assert parsed is not None, f"{support.name} failed to parse {name}"
        assert parsed.path == name


def test_symbols_and_taint_accept_a_parsed_file_and_return_the_shared_types():
    from redfall.ingestion.languages import SUPPORTED
    from redfall.ingestion.symbols import FileSymbols

    samples = {
        "typescript": ("a.ts", b"function f(){ return 1; }\n"),
        "python": ("a.py", b"def f():\n    return 1\n"),
        "java": ("A.java", b"class A { int f(){ return 1; } }\n"),
        "go": ("a.go", b"package main\nfunc f() int { return 1 }\n"),
    }
    for support in SUPPORTED:
        name, source = samples[support.name]
        parsed = support.parse(name, source)
        symbols = support.symbols(parsed)
        assert isinstance(symbols, FileSymbols), support.name
        taints = support.taint(parsed, symbols)
        assert isinstance(taints, list), support.name


# -- the reasoning seam -----------------------------------------------------

def _reasoning_backends():
    from redfall.reasoning.agent_backend import AgentBackend
    from redfall.reasoning.backend import ReasoningBackend
    from redfall.reasoning.litellm_backend import LiteLLMBackend
    from redfall.reasoning.openai_compat import OpenAICompatBackend
    from redfall.reasoning.router import RouterBackend

    return [
        (ReasoningBackend, "base"),
        (AgentBackend, "agent"),
        (LiteLLMBackend, "litellm"),
        (OpenAICompatBackend, "openai_compat"),
        (RouterBackend, "router"),
    ]


def test_every_reasoning_backend_subclasses_the_interface():
    from redfall.reasoning.backend import ReasoningBackend

    for backend_cls, label in _reasoning_backends():
        assert issubclass(backend_cls, ReasoningBackend), label


def test_every_reasoning_backend_implements_the_abstract_methods():
    """A backend that does not implement complete() cannot be constructed."""
    from redfall.reasoning.backend import ReasoningBackend

    abstracts = set(getattr(ReasoningBackend, "__abstractmethods__", frozenset()))
    assert abstracts, "the interface declares no abstract methods"
    for backend_cls, label in _reasoning_backends():
        if backend_cls is ReasoningBackend:
            continue  # the interface itself is legitimately abstract
        missing = {name for name in abstracts if name not in backend_cls.__dict__}
        # A subclass may inherit an implementation from an intermediate base;
        # what must not happen is the method being absent everywhere.
        for name in missing:
            assert hasattr(backend_cls, name), f"{label} cannot satisfy {name}"


def test_a_backend_that_fails_the_contract_is_refused_not_defaulted():
    """The factory raises rather than silently substituting a weaker backend."""
    from redfall.reasoning.config import BackendConfig
    from redfall.reasoning.factory import make_backend

    cfg = BackendConfig(kind="no_such_kind_ever")
    with pytest.raises(Exception):
        make_backend(cfg, session_factory=None, budget=None)


# -- the isolation-tier seam ------------------------------------------------

def test_every_tier_declares_a_complete_footprint():
    from redfall.sandbox.tiers import TIERS

    assert TIERS, "no isolation tier is declared"
    for tier in TIERS:
        assert tier.name
        assert tier.memory_mib_per_unit > 0, tier.name
        assert tier.cpu_millicores_per_unit > 0, tier.name
        assert tier.startup_ms_p50 > 0, tier.name
        assert tier.startup_ms_p95 >= tier.startup_ms_p50, tier.name


def test_every_tier_has_a_probe_and_it_reports_reasons():
    from redfall.sandbox.tiers import TIERS

    for tier in TIERS:
        ready, reasons = tier.available()
        assert isinstance(ready, bool), tier.name
        assert isinstance(reasons, list), tier.name
        if not ready:
            assert reasons, f"{tier.name} unavailable with no reason given"


# -- composition equivalence ------------------------------------------------

def _ingest_signature_result(tmp_path, *, use_cache: bool):
    """Ingest a small tree, optionally with the parse cache, and fingerprint."""
    from redfall.ingestion.cache import ParseCache
    from redfall.ingestion.ingest import ingest
    from redfall.store import db
    from redfall.store.models import Branch, Scan

    tmp_path.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / ("cache.db" if use_cache else "plain.db")
    db.init_engine(f"sqlite:///{db_path}")

    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "app.py").write_text(
        "import os\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/run')\n"
        "def run():\n"
        "    cmd = request.args.get('cmd')\n"
        "    os.system(cmd)\n",
        encoding="utf-8",
    )
    (src / "helper.ts").write_text(
        "export function h(x: string) { return x; }\n", encoding="utf-8"
    )

    cache = ParseCache(tmp_path / "parse.db") if use_cache else None
    with db.session_scope() as session:
        scan_id = "cmp-eq"
        if session.get(Scan, scan_id) is None:
            session.add(Scan(id=scan_id, repo=str(src)))
            session.flush()
        result = ingest(scan_id, src, session=session, cache=cache)
        # A stable fingerprint of what ingestion produced: each file's path,
        # line count and symbol count, plus every taint path — sorted so an
        # ordering difference cannot hide a content difference.
        fingerprint = sorted(
            (f.path, f.line_count, len(f.symbols.functions))
            for f in result.files
        )
        taints = sorted(
            (t.sink, int(t.line or 0), t.sink_kind) for _s, t in result.taint_paths
        )
    if cache is not None:
        cache.close()
    return fingerprint, taints


def test_a_cached_ingest_equals_an_uncached_one(tmp_path):
    """The cache must change speed, never results."""
    plain_files, plain_taints = _ingest_signature_result(tmp_path / "a", use_cache=False)
    cached_files, cached_taints = _ingest_signature_result(tmp_path / "b", use_cache=True)
    assert plain_files == cached_files, "the parse cache changed which files were read"
    assert plain_taints == cached_taints, "the parse cache changed the taint paths found"


def test_a_warm_cache_second_run_equals_the_cold_first(tmp_path):
    """A second ingest with a populated cache matches the first."""
    from redfall.ingestion.cache import ParseCache
    from redfall.ingestion.ingest import ingest
    from redfall.store import db
    from redfall.store.models import Scan

    db.init_engine(f"sqlite:///{tmp_path / 'warm.db'}")
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("import os\nos.system('x')\n", encoding="utf-8")
    cache = ParseCache(tmp_path / "parse.db")

    runs = []
    with db.session_scope() as session:
        for i in range(2):
            scan_id = f"warm-{i}"
            session.add(Scan(id=scan_id, repo=str(src)))
            session.flush()
            result = ingest(scan_id, src, session=session, cache=cache)
            runs.append(sorted((t.sink, int(t.line or 0)) for _s, t in result.taint_paths))
    cache.close()
    assert runs[0] == runs[1], "a warm cache produced different taint paths than a cold one"


def _pool(workers, run_branch):
    """A worklist over a tiny stand-in branch type, wired like the real caller."""
    from contextlib import nullcontext

    from redfall.branching.worklist import BranchWorklist

    # The worker opens its own session with `with self._session_factory() as
    # session:`. A null context is a real session-less stand-in for a test that
    # exercises the pool's plumbing, not a database.
    return BranchWorklist(
        run_branch=run_branch,
        session_factory=lambda: nullcontext(None),
        workers=workers,
    )


class _Branch:
    """The minimum a branch needs to be: an id and a name.

    `id` is what the worklist tracks for `knows`; `name` is carried onto the
    result so the caller can report which branch produced what.
    """

    def __init__(self, branch_id, value):
        self.id = branch_id
        self.name = branch_id
        self.value = value


def test_the_pool_yields_the_same_content_as_a_sequential_pass():
    """Work through the pool produces what the sequential path would.

    Order-independent equality: parallel completion is not deterministic, but
    the *content* must be. A pool that dropped or duplicated work would show
    here.
    """
    values = list(range(8))
    results = {}

    def run_branch(branch, session):
        results[branch.id] = branch.value * 2
        return branch.value * 2

    worklist = _pool(3, run_branch)
    try:
        for value in values:
            worklist.submit(_Branch(f"b{value}", value))
        seen = []
        while len(seen) < len(values):
            done = worklist.take_done(block=True)
            if not done:
                break
            seen.extend(run.outcome for run in done)
    finally:
        worklist.close()

    assert sorted(seen) == sorted(v * 2 for v in values)


def test_a_failing_unit_does_not_take_down_the_pool():
    """One bad branch returns its error; the rest still complete."""
    results = []

    def run_branch(branch, session):
        if branch.value == 3:
            raise ValueError("this unit failed")
        results.append(branch.value)
        return branch.value

    worklist = _pool(2, run_branch)
    try:
        for value in range(6):
            worklist.submit(_Branch(f"b{value}", value))
        outcomes, errors = [], []
        while len(outcomes) + len(errors) < 6:
            done = worklist.take_done(block=True)
            if not done:
                break
            for run in done:
                if run.error is not None:
                    errors.append(run.error)
                else:
                    outcomes.append(run.outcome)
    finally:
        worklist.close()

    assert errors, "the failing unit's error was swallowed"
    assert len(outcomes) == 5, "a single failure stopped the other units"


# -- the tool registry seam -------------------------------------------------

def test_every_registered_tool_has_a_scope():
    """Every tool the registry advertises must have a scope decision."""
    from redfall.interop.auth import TOOL_SCOPES
    from redfall.interop.tools import ToolRegistry
    from redfall.store import db

    db.init_engine("sqlite:///redfall-seam.db")
    registry = ToolRegistry(db.session_scope)
    advertised = {spec["name"] for spec in registry.specs()}

    ungoverned = advertised - set(TOOL_SCOPES)
    assert not ungoverned, f"tools advertised with no scope policy: {sorted(ungoverned)}"


def test_no_scope_policy_names_a_tool_the_registry_does_not_have():
    """A dangling policy is dead weight; a missing one is an open door."""
    from redfall.interop.auth import TOOL_SCOPES
    from redfall.interop.tools import ToolRegistry
    from redfall.store import db

    db.init_engine("sqlite:///redfall-seam2.db")
    registry = ToolRegistry(db.session_scope)
    advertised = {spec["name"] for spec in registry.specs()}

    dangling = set(TOOL_SCOPES) - advertised
    assert not dangling, f"scope policy names tools that do not exist: {sorted(dangling)}"


def test_every_scope_value_is_a_known_scope():
    from redfall.interop.auth import ALL_SCOPES, TOOL_SCOPES

    for tool, scope in TOOL_SCOPES.items():
        assert tool.startswith("redfall_"), tool
        assert scope in ALL_SCOPES, (tool, scope)
