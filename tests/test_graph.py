"""Code graph v1 is built from real ingestion and persisted with provenance."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from redfall.graph.indexer import GraphIndexer
from redfall.graph.query import GraphQuery
from redfall.store.models import Base, GraphEdge, GraphNode

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def session(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'graph.db'}", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with Session() as session:
        yield session
    engine.dispose()


def test_graph_indexes_typescript_source_with_provenance(session):
    snapshot = GraphIndexer(session).index(ROOT / "range" / "vulnbank")
    session.commit()

    assert snapshot.status == "complete"
    assert snapshot.file_count > 0
    assert snapshot.node_count > 0
    assert snapshot.route_count > 0
    assert snapshot.taint_count > 0
    assert "tree-sitter" in snapshot.metadata_json["analyzers"]
    assert "redfall.taint" in snapshot.metadata_json["analyzers"]
    assert "redfall.route-attribution" in snapshot.metadata_json["analyzers"]

    nodes = session.scalars(select(GraphNode).where(GraphNode.snapshot_id == snapshot.id)).all()
    edges = session.scalars(select(GraphEdge).where(GraphEdge.snapshot_id == snapshot.id)).all()
    node_ids = {node.id for node in nodes}
    assert len(nodes) == snapshot.node_count
    assert len(edges) == snapshot.edge_count
    for node in nodes:
        assert node.provenance.get("analyzer")
        assert node.provenance.get("builder") == "redfall.graph.builder"
        assert node.content_hash
    for edge in edges:
        assert edge.source_id in node_ids
        assert edge.target_id in node_ids
        assert edge.content_hash

    routes = GraphQuery(session).routes(snapshot.id)["routes"]
    assert any(item["properties"]["path"] == "/api/auth/login" for item in routes)
    assert all(item["file"] for item in routes)


def test_import_resolution_is_independent_of_ingestion_order(session):
    snapshot = GraphIndexer(session).index(ROOT / "range" / "pythonbank")
    session.commit()
    nodes = {
        node.id: node
        for node in session.scalars(select(GraphNode).where(GraphNode.snapshot_id == snapshot.id)).all()
    }
    edges = session.scalars(
        select(GraphEdge).where(
            GraphEdge.snapshot_id == snapshot.id,
            GraphEdge.kind == "IMPORTS",
        )
    ).all()
    imports = {
        (nodes[edge.source_id].file, nodes[edge.target_id].file)
        for edge in edges
        if nodes[edge.target_id].kind == "File"
    }
    # app.py is ingested before db.py and routes/*.py; the graph still resolves
    # both the relative from-import and the package import.
    assert ("src/pythonbank/app.py", "src/pythonbank/db.py") in imports
    assert ("src/pythonbank/app.py", "src/pythonbank/routes/auth.py") in imports
    assert ("src/pythonbank/routes/reports.py", "src/pythonbank/core/reports.py") in imports


def test_route_reaches_taint_sink_path_is_traceable(session):
    snapshot = GraphIndexer(session).index(ROOT / "range" / "pythonbank")
    session.commit()
    query = GraphQuery(session)
    reaches = session.scalars(
        select(GraphEdge).where(
            GraphEdge.snapshot_id == snapshot.id,
            GraphEdge.kind == "REACHES",
        )
    ).first()
    assert reaches is not None

    route = query.get_node(snapshot.id, reaches.source_id)
    sink = query.get_node(snapshot.id, reaches.target_id)
    assert route.kind == "Route"
    assert sink.kind == "Sink"
    paths = query.paths(
        snapshot.id,
        route.id,
        sink.id,
        max_depth=2,
        edge_kinds=["REACHES"],
        limit=3,
    )
    assert paths["paths"]
    assert paths["paths"][0]["length"] == 1
    assert paths["paths"][0]["edges"][0]["provenance"]["analyzer"] == "redfall.route-attribution"

    neighbors = query.neighbors(snapshot.id, route.id, edge_kinds=["REACHES"], limit=10)
    assert sink.id in {item["id"] for item in neighbors["nodes"]}


def test_traversal_ignores_dangling_edges_and_does_not_inflate_depth(session):
    snapshot = GraphIndexer(session).index(ROOT / "range" / "pythonbank")
    session.commit()
    query = GraphQuery(session)
    reaches = session.scalars(
        select(GraphEdge).where(
            GraphEdge.snapshot_id == snapshot.id,
            GraphEdge.kind == "REACHES",
        )
    ).all()
    assert reaches
    route = query.get_node(snapshot.id, reaches[0].source_id)
    targets = {edge.target_id for edge in reaches if edge.source_id == route.id}
    assert targets
    for target_id in targets:
        target = session.get(GraphNode, target_id)
        if target is not None:
            session.delete(target)
    session.flush()

    result = query.neighbors(
        snapshot.id,
        route.id,
        edge_kinds=["REACHES"],
        depth=1,
    )
    assert result["depth"] == 0
    assert result["edges"] == []


def test_search_stats_inventory_and_self_diff(session):
    indexer = GraphIndexer(session)
    first = indexer.index(ROOT / "range" / "pythonbank")
    second = indexer.index(ROOT / "range" / "pythonbank")
    session.commit()
    query = GraphQuery(session)

    stats = query.stats(first.id)
    assert stats["coverage"]["files"] == first.file_count
    assert stats["nodes_by_kind"]["Route"] == first.route_count
    assert stats["coverage"]["sources"] > 0
    assert stats["coverage"]["sinks"] > 0

    found = query.search(snapshot_id=first.id, query="login", kind="Route", limit=10)
    assert found["returned"] >= 1
    assert all(item["kind"] == "Route" for item in found["nodes"])

    inventory = query.inventory(first.id, limit=10)
    assert inventory["routes"]
    assert inventory["dependencies"] == []
    bounded = query.inventory(first.id, limit=1)
    assert bounded["truncated"] is True
    assert len(bounded["files"]) == 1

    latest = query.list_snapshots(root=str(ROOT / "range" / "pythonbank"), limit=2)
    assert {item["id"] for item in latest} == {first.id, second.id}

    diff = query.diff(first.id, second.id)
    assert diff["summary"] == {
        "nodes_added": 0,
        "nodes_removed": 0,
        "nodes_changed": 0,
        "edges_added": 0,
        "edges_removed": 0,
        "edges_changed": 0,
    }
    assert diff["base"]["content_digest"] == diff["head"]["content_digest"]


def test_graph_snapshot_rows_are_immutable_across_second_index(session):
    first = GraphIndexer(session).index(ROOT / "range" / "vulnbank")
    session.commit()
    first_nodes = {
        node.id
        for node in session.scalars(select(GraphNode).where(GraphNode.snapshot_id == first.id)).all()
    }
    second = GraphIndexer(session).index(ROOT / "range" / "vulnbank")
    session.commit()
    second_nodes = {
        node.id
        for node in session.scalars(select(GraphNode).where(GraphNode.snapshot_id == second.id)).all()
    }
    assert first.id != second.id
    assert first_nodes.isdisjoint(second_nodes)
