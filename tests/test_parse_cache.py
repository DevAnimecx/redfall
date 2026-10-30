"""The parse cache must be invisible: a hit and a miss agree exactly.

A cache that returns something subtly different from a fresh parse is worse
than no cache, because the difference shows up as a finding that reproduces
once and not again. So the central test here ingests the same tree twice and
asserts the two results are equal field by field, not merely close.

The cache is optional throughout. A scan with no cache, or with a cache it
cannot read, parses everything — that path is covered too, because it is the
one that runs when something has gone wrong.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "range"))


@pytest.fixture()
def source_tree(tmp_path) -> Path:
    app = tmp_path / "app"
    (app / "src").mkdir(parents=True)
    (app / "src" / "app.py").write_text(
        "import os\n"
        "from flask import Flask, request\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/run')\n"
        "def run():\n"
        "    cmd = request.args.get('cmd')\n"
        "    return os.system(cmd)\n",
        encoding="utf-8",
    )
    (app / "src" / "util.py").write_text(
        "def add(a, b):\n    return a + b\n",
        encoding="utf-8",
    )
    return app


def _digest(result) -> dict:
    """A comparable summary of an ingest result, order-independent."""
    return {
        "files": sorted(
            (
                f.path,
                f.line_count,
                f.size_bytes,
                len(f.symbols.routes),
                len(f.symbols.functions),
                len(f.symbols.calls),
                len(f.symbols.imports),
                [(t.source, t.sink, t.line) for t in f.taints],
            )
            for f in result.files
        ),
        "errors": sorted(result.parse_errors),
    }


def test_cache_hit_matches_a_fresh_parse(source_tree, tmp_path):
    """The whole contract: a cached ingest equals an uncached one."""
    from redfall.ingestion.cache import ParseCache
    from redfall.ingestion.ingest import ingest

    fresh = ingest("scan-plain", source_tree)

    cache = ParseCache(tmp_path / "cache.db")
    try:
        first = ingest("scan-cold", source_tree, cache=cache)
        second = ingest("scan-warm", source_tree, cache=cache)
    finally:
        cache.close()

    # The ids differ per scan, so compare everything else.
    assert _digest(first) == _digest(fresh)
    assert _digest(second) == _digest(fresh)


def test_the_second_ingest_is_served_from_the_cache(source_tree, tmp_path):
    from redfall.ingestion.cache import ParseCache
    from redfall.ingestion.ingest import ingest

    cache = ParseCache(tmp_path / "cache.db")
    try:
        ingest("scan-cold", source_tree, cache=cache)
        assert cache.hits == 0, "the first ingest should have missed everything"
        cold_misses = cache.misses
        assert cold_misses > 0

        ingest("scan-warm", source_tree, cache=cache)
        assert cache.hits == cold_misses, "the second ingest should have hit every file"
    finally:
        cache.close()


def test_a_changed_file_is_reparsed(source_tree, tmp_path):
    """Stale symbols are how a fixed bug looks unfixed, or vice versa."""
    from redfall.ingestion.cache import ParseCache
    from redfall.ingestion.ingest import ingest

    cache = ParseCache(tmp_path / "cache.db")
    try:
        first = ingest("scan-1", source_tree, cache=cache)
        before = {f.path: len(f.taints) for f in first.files}
        assert before["src/app.py"] == 1, "the seeded taint path should be found"

        (source_tree / "src" / "app.py").write_text(
            "from flask import Flask\n\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/safe')\n"
            "def safe():\n"
            "    return 'ok'\n",
            encoding="utf-8",
        )
        second = ingest("scan-2", source_tree, cache=cache)
        after = {f.path: len(f.taints) for f in second.files}

        assert after["src/app.py"] == 0, "the removed sink must not survive from the cache"
        assert after["src/util.py"] == 0
    finally:
        cache.close()


def test_unchanged_files_keep_their_parse_while_one_file_changes(source_tree, tmp_path):
    from redfall.ingestion.cache import ParseCache
    from redfall.ingestion.ingest import ingest

    cache = ParseCache(tmp_path / "cache.db")
    try:
        ingest("scan-1", source_tree, cache=cache)
        hits_before = cache.hits

        (source_tree / "src" / "util.py").write_text(
            "def add(a, b):\n    return a + b + 1\n", encoding="utf-8"
        )
        ingest("scan-2", source_tree, cache=cache)

        # One file changed of two, so exactly one hit.
        assert cache.hits - hits_before == 1
    finally:
        cache.close()


def test_the_same_bytes_at_a_different_path_are_a_different_key():
    """Symbols depend on path: the same bytes mounted elsewhere differ."""
    from redfall.ingestion.cache import content_key

    body = b"@app.route('/x')\ndef h():\n    return 1\n"
    assert content_key("src/a.py", body, language="python") != content_key(
        "src/b.py", body, language="python"
    )


def test_a_different_language_is_a_different_key():
    """Two grammars may read the same file; their results are not interchangeable."""
    from redfall.ingestion.cache import content_key

    body = b"x = 1\n"
    assert content_key("a.py", body, language="python") != content_key(
        "a.py", body, language="typescript"
    )


def test_a_corrupt_entry_is_reparsed_not_trusted(source_tree, tmp_path):
    """A cache is a file written earlier; it must never be believed blindly."""
    from redfall.ingestion.cache import ParseCache, content_key
    from redfall.ingestion.ingest import ingest

    cache = ParseCache(tmp_path / "cache.db")
    try:
        ingest("scan-1", source_tree, cache=cache)
        source = (source_tree / "src" / "app.py").read_bytes()
        key = content_key("src/app.py", source, language="python")

        # Corrupt the stored payload the way a partial write or a bad disk would.
        cache._conn.execute(
            "UPDATE parses SET payload = ? WHERE key = ?", ("{not json", key)
        )
        cache._conn.commit()

        result = ingest("scan-2", source_tree, cache=cache)
        taints = {f.path: len(f.taints) for f in result.files}
        assert taints["src/app.py"] == 1, "the corrupt entry must not suppress the taint"
        assert not result.parse_errors
    finally:
        cache.close()


def test_an_entry_from_an_older_shape_is_reparsed(source_tree, tmp_path):
    """Adding a field must invalidate rather than half-populate an old entry."""
    from redfall.ingestion.cache import ParseCache, content_key
    from redfall.ingestion.ingest import ingest

    cache = ParseCache(tmp_path / "cache.db")
    try:
        ingest("scan-1", source_tree, cache=cache)
        source = (source_tree / "src" / "util.py").read_bytes()
        key = content_key("src/util.py", source, language="python")

        # A payload missing a field a later release added.
        cache._conn.execute(
            "UPDATE parses SET payload = ? WHERE key = ?",
            (json.dumps({"line_count": 2, "size_bytes": 10, "path": "src/util.py"}), key),
        )
        cache._conn.commit()

        result = ingest("scan-2", source_tree, cache=cache)
        functions = {f.path: len(f.symbols.functions) for f in result.files}
        assert functions["src/util.py"] == 1
        assert not result.parse_errors
    finally:
        cache.close()


def test_prune_bounds_the_cache(source_tree, tmp_path):
    """An unbounded cache is a disk leak with no upside."""
    from redfall.ingestion.cache import ParseCache
    from redfall.ingestion.ingest import ingest

    cache = ParseCache(tmp_path / "cache.db")
    try:
        for i in range(6):
            (source_tree / "src" / f"f{i}.py").write_text(f"x = {i}\n", encoding="utf-8")
        ingest("scan-1", source_tree, cache=cache)
        assert cache.stats()["entries"] >= 6

        removed = cache.prune(keep=3)
        assert removed >= 1
        assert cache.stats()["entries"] <= 3
    finally:
        cache.close()


def test_no_cache_still_ingests(source_tree):
    """The cache is an optimisation; its absence must change nothing."""
    from redfall.ingestion.ingest import ingest

    result = ingest("scan-plain", source_tree)
    assert {f.path for f in result.files} == {"src/app.py", "src/util.py"}
    assert not result.parse_errors


def test_a_cache_in_an_unwritable_place_does_not_fail_the_ingest(source_tree, tmp_path):
    """A scan must not depend on being able to write a cache file."""
    from redfall.ingestion.cache import ParseCache
    from redfall.ingestion.ingest import ingest

    cache = ParseCache(tmp_path / "cache.db")
    try:
        ingest("scan-1", source_tree, cache=cache)
        # Close the connection underneath the cache: every later write fails.
        cache._conn.close()
        result = ingest("scan-2", source_tree, cache=cache)
        assert {f.path for f in result.files} == {"src/app.py", "src/util.py"}
    finally:
        pass
