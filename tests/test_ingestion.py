"""Ingestion must find real structure in the real target. No fixtures."""

from __future__ import annotations


def test_parses_every_source_file(ingest_result):
    assert len(ingest_result.files) >= 20
    assert ingest_result.parse_errors == []


def test_finds_the_vuln_001_taint_path(ingest_result):
    """The §6.1 acceptance case: req.body reaching pool.query in loginHandler."""
    hits = [
        (rel, t)
        for rel, t in ingest_result.taint_paths
        if rel == "src/routes/auth.ts" and t.sink == "pool.query" and t.symbol == "loginHandler"
    ]
    assert hits, "no taint path from req.body to pool.query in loginHandler"
    rel, taint = hits[0]
    assert taint.source == "req.body"
    # The manifest anchors VULN-001 at auth.ts:38; the sink is a few lines on.
    assert abs(taint.line - 38) <= 5, f"sink at line {taint.line} is outside the matcher tolerance"


def test_finds_the_command_injection_sink(ingest_result):
    hits = [t for rel, t in ingest_result.taint_paths if rel == "src/routes/admin.ts" and t.sink_kind == "exec"]
    assert hits, "no exec sink found in admin.ts"
    assert hits[0].source == "req.body"


def test_resolves_router_mounts_to_full_urls(ingest_result):
    urls = {f"{r['method']} {r['path']}" for r in ingest_result.http_routes()}
    for expected in ("POST /api/auth/login", "POST /api/admin/exec", "GET /api/users/search", "POST /api/webhook/stripe"):
        assert expected in urls, f"{expected} missing from {sorted(urls)}"


def test_route_resolution_is_not_guessed(ingest_result):
    """A mount that cannot be resolved must not produce a made-up prefix."""
    for prefix in ingest_result.mount_prefixes.values():
        assert prefix.startswith("/"), f"mount prefix {prefix!r} does not look like a URL prefix"


def test_taint_paths_attach_to_a_reachable_route(ingest_result):
    """Every proven sink should be reachable from at least one HTTP route."""
    unreachable = []
    for rel, taint in ingest_result.taint_paths:
        if not ingest_result.routes_for_line(rel, taint.line):
            unreachable.append(f"{rel}:{taint.line}")
    assert not unreachable, f"taint paths with no owning route: {unreachable}"


def test_dependency_versions_are_resolved_from_disk(ingest_result):
    resolved = {d.name: d.resolved for d in ingest_result.security_relevant_deps()}
    assert resolved.get("express"), "express version not resolved from node_modules"
    assert resolved.get("jsonwebtoken"), "jsonwebtoken version not resolved"
    # Resolved means the installed version, not the declared range.
    assert not resolved["express"].startswith("^"), f"express resolved to a range: {resolved['express']}"


def test_scripts_directory_is_not_attack_surface(ingest_result):
    """The range's own tooling is not part of the scanned application."""
    paths = {f.path for f in ingest_result.files}
    assert not any(p.startswith("scripts/") for p in paths)
    assert not any(p.startswith("tests/") for p in paths)


def test_symbols_are_persisted_with_unique_ids(ingest_result):
    from sqlalchemy.orm import sessionmaker

    from redfall.store.db import init_engine
    from redfall.store.models import Symbol

    import os

    url = os.getenv("REDFALL_TEST_DATABASE_URL", "postgresql+psycopg://redfall:redfall@localhost:5432/redfall")
    engine = init_engine(url)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)

    from redfall.ingestion.ingest import ingest as do_ingest
    from redfall.store.models import Scan

    with Session() as session:
        session.query(Scan).filter(Scan.id == "test-persist").delete()
        session.flush()
        session.add(Scan(id="test-persist", repo="range/vulnbank", commit=""))
        session.flush()
        do_ingest("test-persist", ingest_result.target, session)
        ids = [row[0] for row in session.query(Symbol.id).filter(Symbol.scan_id == "test-persist").all()]
    assert ids, "no symbols persisted"
    assert len(ids) == len(set(ids)), "duplicate symbol primary keys"
