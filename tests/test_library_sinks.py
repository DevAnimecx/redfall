"""Sink inference from a project's declared dependencies.

This is the fix for the generalisation gap. A fixed receiver table recognises
the libraries somebody enumerated and is blind to every other one — NodeGoat
fetches with `needle`, which produced **zero** classified sinks, and a scanner
that reports no sinks is indistinguishable from an application with no bugs.

The tests that matter are the negative ones. A false sink produces a taint path
to something that cannot be exploited, which is the finding this project most
wants to avoid; the safe direction is to leave a library unknown.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


# -- the inference ----------------------------------------------------------

def test_a_known_library_keeps_its_kind():
    from redfall.ingestion.library_sinks import classify_library

    assert classify_library("axios").kind == "fetch"
    assert classify_library("pg").kind == "db"
    assert classify_library("shelljs").kind == "exec"


def test_a_library_nobody_enumerated_is_inferred_from_its_name():
    """The point of the whole module: `needle` was in no table anywhere."""
    from redfall.ingestion.library_sinks import classify_library

    inferred = classify_library("needle")
    assert inferred is not None
    assert inferred.kind == "fetch"


def test_the_inference_generalises_to_names_never_seen():
    from redfall.ingestion.library_sinks import classify_library

    for name, kind in (
        ("cross-fetch", "fetch"),
        ("isomorphic-fetch", "fetch"),
        ("request-promise-native", "fetch"),
        ("pg-pool", "db"),
        ("redis-client", "db"),
        ("child-process-promise", "exec"),
        ("filesystem-extra", "fs"),
    ):
        got = classify_library(name)
        assert got is not None and got.kind == kind, f"{name} -> {got}"


def test_a_scope_prefix_is_stripped():
    from redfall.ingestion.library_sinks import classify_library

    inferred = classify_library("@sindresorhus/got")
    assert inferred is not None and inferred.kind == "fetch"


# -- the refusals, which matter more ----------------------------------------

def test_a_library_that_is_not_a_sink_stays_unknown():
    from redfall.ingestion.library_sinks import classify_library

    for name in ("underscore", "body-parser", "swig", "helmet", "express", "passport"):
        assert classify_library(name) is None, f"{name} was classified as a sink"


def test_a_test_double_is_never_a_sink():
    """`jest-fetch-mock` names a fetch library and is not one."""
    from redfall.ingestion.library_sinks import classify_library

    for name in ("jest-fetch-mock", "fetch-mock", "request-stub", "fake-http"):
        assert classify_library(name) is None, f"{name} was classified as a sink"


def test_a_type_package_is_never_a_sink():
    """`@types/request` is type declarations with no runtime code at all.

    The scope prefix is the signal, and `_normalise` strips it — so the check
    has to run against the raw name as well. Checking only the normalised name
    classified it as an HTTP client.
    """
    from redfall.ingestion.library_sinks import classify_library

    assert classify_library("@types/request") is None
    assert classify_library("@types/node-fetch") is None
    assert classify_library("typescript-http-types") is None


def test_a_lint_plugin_is_never_a_sink():
    from redfall.ingestion.library_sinks import classify_library

    assert classify_library("eslint-plugin-fetch") is None
    assert classify_library("prettier-plugin-sql") is None


def test_a_stem_inside_a_longer_word_does_not_match():
    """Whole-word matching, not substring.

    A substring test classifies `prefetch-cache` as an HTTP client and
    `filesystem-watcher-lite` as an fs library, and both produce taint paths
    that cannot be exploited.
    """
    from redfall.ingestion.library_sinks import classify_library

    assert classify_library("prefetch-cache") is None
    assert classify_library("postgresql-migrations-lite") is not None  # a real stem
    assert classify_library("notafetchlibrary") is None


def test_an_empty_name_classifies_to_nothing():
    from redfall.ingestion.library_sinks import classify_library

    assert classify_library("") is None
    assert classify_library("   ") is None


# -- reading a manifest -----------------------------------------------------

def test_dependencies_are_read_from_a_package_json(tmp_path):
    from redfall.ingestion.library_sinks import libraries_from_manifest

    (tmp_path / "package.json").write_text(
        '{"dependencies": {"needle": "2.2.4", "express": "^4.13"}, '
        '"devDependencies": {"jest-fetch-mock": "^1.0"}}',
        encoding="utf-8",
    )
    declared = libraries_from_manifest(tmp_path / "package.json")
    assert "needle" in declared
    assert "express" in declared
    assert "jest-fetch-mock" in declared


def test_a_malformed_manifest_returns_nothing_rather_than_raising(tmp_path):
    """A manifest is one input among several; a bad one must not end a scan."""
    from redfall.ingestion.library_sinks import libraries_from_manifest

    (tmp_path / "package.json").write_text("{not json", encoding="utf-8")
    assert libraries_from_manifest(tmp_path / "package.json") == {}


def test_a_missing_manifest_returns_nothing(tmp_path):
    from redfall.ingestion.library_sinks import libraries_from_manifest

    assert libraries_from_manifest(tmp_path / "package.json") == {}


def test_requirements_txt_is_read(tmp_path):
    from redfall.ingestion.library_sinks import libraries_from_manifest

    (tmp_path / "requirements.txt").write_text(
        "# a comment\nrequests==2.31.0\npsycopg[binary]>=3.1\n-r other.txt\n",
        encoding="utf-8",
    )
    declared = libraries_from_manifest(tmp_path / "requirements.txt")
    assert "requests" in declared
    assert "psycopg" in declared
    assert not any(name.startswith("-") for name in declared)


def test_vendored_trees_are_not_scanned_for_manifests(tmp_path):
    from redfall.ingestion.library_sinks import library_sinks

    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text('{"dependencies": {"needle": "1"}}', encoding="utf-8")
    vendored = app / "node_modules" / "inner"
    vendored.mkdir(parents=True)
    (vendored / "package.json").write_text(
        '{"dependencies": {"some-http-client": "1"}}', encoding="utf-8"
    )
    found = library_sinks(tmp_path)
    assert "needle" in found
    assert "some-http-client" not in found


# -- the wiring -------------------------------------------------------------

def test_the_registry_is_empty_until_a_tree_is_walked():
    """An unset vocabulary means the built-in tables only — the prior behaviour."""
    from redfall.ingestion import symbols

    symbols.clear_library_kinds()
    assert symbols.library_kind("needle") is None


def test_the_registry_reports_what_was_set_and_clears():
    from redfall.ingestion import symbols

    symbols.use_library_kinds({"needle": "fetch"})
    assert symbols.library_kind("needle") == "fetch"
    assert symbols.library_kind("NEEDLE") == "fetch", "lookup must be case-insensitive"
    symbols.clear_library_kinds()
    assert symbols.library_kind("needle") is None


def test_both_sink_classifiers_agree_on_a_declared_library():
    """The bug this fixed.

    `symbols.py` and `taint.py` each grew their own sink classifier and only
    one learned about declared libraries — so the first reported `needle.get`
    as a fetch sink while the second, which decides whether a taint path
    exists, returned None. The finding never appeared.
    """
    from redfall.ingestion import symbols as symbols_mod
    from redfall.ingestion.parser_ts import parse_source
    from redfall.ingestion.taint import _sink_label

    source = b'const needle = require("needle");\nneedle.get(url);\n'
    parsed = parse_source("a.js", source)

    symbols_mod.clear_library_kinds()
    # Without the vocabulary, the built-in tables do not know `needle`.
    assert not any(
        node.type == "call_expression" and _sink_label(parsed, node)
        for node in parsed.walk()
        if node.type == "call_expression" and "needle" in parsed.text_of(node)
    )

    symbols_mod.use_library_kinds({"needle": "fetch"})
    labelled = [
        _sink_label(parsed, node)
        for node in parsed.walk()
        if node.type == "call_expression" and "needle" in parsed.text_of(node)
    ]
    symbols_mod.clear_library_kinds()
    assert any(label and label[1] == "fetch" for label in labelled), (
        "the taint stage does not consult the declared-library vocabulary"
    )


@pytest.mark.skipif(
    not (ROOT / "sandbox" / "challenges" / "nodegoat").is_dir(),
    reason="nodegoat not fetched",
)
def test_a_real_apps_fetch_library_is_recognised():
    """NodeGoat fetches with `needle`; the engine must see it as a sink."""
    from redfall.ingestion.library_sinks import library_sinks

    found = library_sinks(ROOT / "sandbox" / "challenges" / "nodegoat")
    assert "needle" in found
    assert found["needle"].kind == "fetch"
