"""Query the persisted code graph with bounded, explainable traversals.

There is no hidden in-memory graph and no recursive SQL that differs between
SQLite and Postgres. Queries read the stored snapshot, traverse in Python with a
hard node/edge budget, and say `truncated` when the budget stopped them. A caller
can always inspect the snapshot and the provenance of every returned item.
"""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Iterable

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..store.models import GraphEdge, GraphNode, GraphSnapshot
from .schema import EDGE_KINDS, NODE_KINDS


class GraphQueryError(RuntimeError):
    """A graph query cannot be answered as requested."""


def _chunks(items: list[str], size: int = 400) -> Iterable[list[str]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _limits(limit: int, maximum: int) -> int:
    if limit < 1:
        raise GraphQueryError("limit must be at least 1")
    return min(limit, maximum)


class GraphQuery:
    def __init__(self, session: Session) -> None:
        self.session = session

    # ------------------------------------------------------------- snapshots
    def snapshot(
        self,
        snapshot_id: str | None = None,
        *,
        campaign_id: str | None = None,
        root: str | None = None,
    ) -> GraphSnapshot:
        if snapshot_id:
            row = self.session.get(GraphSnapshot, snapshot_id)
            if row is None:
                raise GraphQueryError(f"graph snapshot not found: {snapshot_id}")
            return row
        stmt = select(GraphSnapshot).order_by(GraphSnapshot.created_at.desc()).limit(1)
        if campaign_id:
            stmt = stmt.where(GraphSnapshot.campaign_id == campaign_id)
        if root:
            stmt = stmt.where(GraphSnapshot.root == str(Path(root).expanduser().resolve()))
        row = self.session.scalars(stmt).first()
        if row is None:
            raise GraphQueryError("no graph snapshot exists for this query")
        return row

    def list_snapshots(
        self,
        *,
        campaign_id: str | None = None,
        root: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, object]]:
        count = _limits(limit, 200)
        stmt = select(GraphSnapshot).order_by(GraphSnapshot.created_at.desc()).limit(count)
        if campaign_id:
            stmt = stmt.where(GraphSnapshot.campaign_id == campaign_id)
        if root:
            stmt = stmt.where(
                GraphSnapshot.root == str(Path(root).expanduser().resolve())
            )
        return [row.to_wire() for row in self.session.scalars(stmt)]

    def stats(self, snapshot_id: str | None = None, *, campaign_id: str | None = None) -> dict[str, object]:
        snapshot = self.snapshot(snapshot_id, campaign_id=campaign_id)
        node_rows = self.session.execute(
            select(GraphNode.kind, func.count())
            .where(GraphNode.snapshot_id == snapshot.id)
            .group_by(GraphNode.kind)
        ).all()
        edge_rows = self.session.execute(
            select(GraphEdge.kind, func.count())
            .where(GraphEdge.snapshot_id == snapshot.id)
            .group_by(GraphEdge.kind)
        ).all()
        by_kind = {kind: count for kind, count in node_rows}
        return {
            "snapshot": snapshot.to_wire(),
            "nodes_by_kind": by_kind,
            "edges_by_kind": {kind: count for kind, count in edge_rows},
            "coverage": {
                "files": snapshot.file_count,
                "routes": snapshot.route_count,
                "sources": by_kind.get("Source", 0),
                "sanitizers": by_kind.get("Sanitizer", 0),
                "sinks": by_kind.get("Sink", 0),
                "taint_flows": snapshot.taint_count,
            },
        }

    # ---------------------------------------------------------------- search
    def search(
        self,
        *,
        snapshot_id: str | None = None,
        query: str = "",
        kind: str = "",
        file: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, object]:
        snapshot = self.snapshot(snapshot_id)
        count = _limits(limit, 200)
        if kind and kind not in NODE_KINDS:
            raise GraphQueryError(f"unknown node kind: {kind}")
        if offset < 0:
            raise GraphQueryError("offset must not be negative")
        stmt = select(GraphNode).where(GraphNode.snapshot_id == snapshot.id)
        if kind:
            stmt = stmt.where(GraphNode.kind == kind)
        if file:
            stmt = stmt.where(GraphNode.file.contains(file))
        if query:
            pattern = f"%{query}%"
            stmt = stmt.where(
                or_(
                    GraphNode.name.ilike(pattern),
                    GraphNode.key.ilike(pattern),
                    GraphNode.file.ilike(pattern),
                )
            )
        stmt = stmt.order_by(GraphNode.kind, GraphNode.name, GraphNode.line).offset(offset).limit(count)
        rows = self.session.scalars(stmt).all()
        return {
            "snapshot_id": snapshot.id,
            "query": query,
            "kind": kind,
            "file": file,
            "offset": offset,
            "limit": count,
            "returned": len(rows),
            "nodes": [row.to_wire() for row in rows],
        }

    # ------------------------------------------------------------------ node
    def get_node(self, snapshot_id: str, node_ref: str) -> GraphNode:
        node = self.session.get(GraphNode, node_ref)
        if node is None and ":" in node_ref:
            kind, key = node_ref.split(":", 1)
            node = self.session.scalars(
                select(GraphNode).where(
                    GraphNode.snapshot_id == snapshot_id,
                    GraphNode.kind == kind,
                    GraphNode.key == key,
                )
            ).first()
        if node is None:
            node = self.session.scalars(
                select(GraphNode).where(
                    GraphNode.snapshot_id == snapshot_id,
                    GraphNode.key == node_ref,
                )
            ).first()
        if node is None or node.snapshot_id != snapshot_id:
            raise GraphQueryError(f"graph node not found in snapshot: {node_ref}")
        return node

    def node_detail(self, snapshot_id: str, node_ref: str) -> dict[str, object]:
        node = self.get_node(snapshot_id, node_ref)
        outgoing = self.session.scalars(
            select(GraphEdge)
            .where(GraphEdge.snapshot_id == snapshot_id, GraphEdge.source_id == node.id)
            .order_by(GraphEdge.kind, GraphEdge.line)
        ).all()
        incoming = self.session.scalars(
            select(GraphEdge)
            .where(GraphEdge.snapshot_id == snapshot_id, GraphEdge.target_id == node.id)
            .order_by(GraphEdge.kind, GraphEdge.line)
        ).all()
        return {
            "node": node.to_wire(),
            "outgoing": [edge.to_wire() for edge in outgoing],
            "incoming": [edge.to_wire() for edge in incoming],
        }

    # -------------------------------------------------------------- traversal
    def _edges_from(
        self,
        snapshot_id: str,
        node_ids: list[str],
        direction: str,
        edge_kinds: list[str] | None,
    ) -> list[GraphEdge]:
        out: list[GraphEdge] = []
        for chunk in _chunks(node_ids):
            if direction in {"out", "both"}:
                stmt = select(GraphEdge).where(
                    GraphEdge.snapshot_id == snapshot_id,
                    GraphEdge.source_id.in_(chunk),
                )
                if edge_kinds:
                    stmt = stmt.where(GraphEdge.kind.in_(edge_kinds))
                out.extend(self.session.scalars(stmt).all())
            if direction in {"in", "both"}:
                stmt = select(GraphEdge).where(
                    GraphEdge.snapshot_id == snapshot_id,
                    GraphEdge.target_id.in_(chunk),
                )
                if edge_kinds:
                    stmt = stmt.where(GraphEdge.kind.in_(edge_kinds))
                out.extend(self.session.scalars(stmt).all())
        unique: dict[str, GraphEdge] = {edge.id: edge for edge in out}
        return list(unique.values())

    def neighbors(
        self,
        snapshot_id: str,
        node_ref: str,
        *,
        direction: str = "both",
        edge_kinds: list[str] | None = None,
        depth: int = 1,
        limit: int = 200,
    ) -> dict[str, object]:
        if direction not in {"out", "in", "both"}:
            raise GraphQueryError("direction must be out, in or both")
        if edge_kinds:
            unknown = set(edge_kinds) - EDGE_KINDS
            if unknown:
                raise GraphQueryError(f"unknown edge kind: {sorted(unknown)[0]}")
        if depth < 1 or depth > 6:
            raise GraphQueryError("depth must be between 1 and 6")
        cap = _limits(limit, 1000)
        start = self.get_node(snapshot_id, node_ref)
        nodes: dict[str, GraphNode] = {start.id: start}
        edges: dict[str, GraphEdge] = {}
        frontier = {start.id}
        truncated = False
        reached = 0
        for level in range(1, depth + 1):
            if not frontier:
                break
            level_edges = self._edges_from(snapshot_id, sorted(frontier), direction, edge_kinds)
            if not level_edges:
                break
            next_frontier: set[str] = set()
            for edge in level_edges:
                neighbor_id = edge.target_id if edge.source_id in frontier else edge.source_id
                if neighbor_id not in nodes:
                    next_frontier.add(neighbor_id)
            for chunk in _chunks(sorted(next_frontier)):
                for row in self.session.scalars(
                    select(GraphNode).where(GraphNode.id.in_(chunk))
                ):
                    nodes[row.id] = row
            # Drop an edge whose other endpoint no longer exists. Otherwise a
            # dangling row would inflate the reported depth while returning no
            # node or edge to the caller.
            valid_edges = [
                edge
                for edge in level_edges
                if edge.source_id in nodes and edge.target_id in nodes
            ]
            if not valid_edges:
                break
            for edge in valid_edges:
                edges[edge.id] = edge
            reached = level
            if len(nodes) > cap:
                extra = list(nodes)[cap:]
                for node_id in extra:
                    nodes.pop(node_id, None)
                truncated = True
                break
            frontier = {node_id for node_id in next_frontier if node_id in nodes}
        present = set(nodes)
        return {
            "snapshot_id": snapshot_id,
            "start": start.to_wire(),
            "direction": direction,
            "depth": reached,
            "truncated": truncated,
            "nodes": [node.to_wire() for node in nodes.values()],
            "edges": [
                edge.to_wire()
                for edge in edges.values()
                if edge.source_id in present and edge.target_id in present
            ],
        }

    def paths(
        self,
        snapshot_id: str,
        source_ref: str,
        target_ref: str,
        *,
        max_depth: int = 5,
        edge_kinds: list[str] | None = None,
        limit: int = 10,
    ) -> dict[str, object]:
        if max_depth < 1 or max_depth > 8:
            raise GraphQueryError("max_depth must be between 1 and 8")
        cap = _limits(limit, 50)
        if edge_kinds:
            unknown = set(edge_kinds) - EDGE_KINDS
            if unknown:
                raise GraphQueryError(f"unknown edge kind: {sorted(unknown)[0]}")
        source = self.get_node(snapshot_id, source_ref)
        target = self.get_node(snapshot_id, target_ref)
        if source.id == target.id:
            return {
                "snapshot_id": snapshot_id,
                "paths": [{"nodes": [source.to_wire()], "edges": [], "length": 0}],
                "truncated": False,
            }

        adjacency: dict[str, list[GraphEdge]] = {}
        node_cache: dict[str, GraphNode] = {source.id: source, target.id: target}
        paths_found: list[dict[str, object]] = []
        stack: list[tuple[str, list[str], list[str]]] = [(source.id, [source.id], [])]
        expansions = 0
        max_expansions = min(20000, max(500, max_depth * cap * 100))
        truncated = False
        while stack and len(paths_found) < cap:
            current, node_path, edge_path = stack.pop()
            if len(edge_path) >= max_depth:
                continue
            if current not in adjacency:
                rows = self.session.scalars(
                    select(GraphEdge).where(
                        GraphEdge.snapshot_id == snapshot_id,
                        GraphEdge.source_id == current,
                    )
                ).all()
                if edge_kinds:
                    rows = [edge for edge in rows if edge.kind in edge_kinds]
                adjacency[current] = list(rows)
            for edge in adjacency[current]:
                expansions += 1
                if expansions > max_expansions:
                    truncated = True
                    break
                neighbor = edge.target_id
                if neighbor in node_path:
                    continue
                neighbor_node = node_cache.get(neighbor)
                if neighbor_node is None:
                    neighbor_node = self.session.get(GraphNode, neighbor)
                    if neighbor_node is None or neighbor_node.snapshot_id != snapshot_id:
                        continue
                    node_cache[neighbor] = neighbor_node
                next_nodes = node_path + [neighbor]
                next_edges = edge_path + [edge.id]
                if neighbor == target.id:
                    paths_found.append(
                        {
                            "nodes": [
                                node_cache[node_id].to_wire()
                                for node_id in next_nodes
                                if node_id in node_cache
                            ],
                            "edges": [
                                edge.to_wire()
                                for edge in (
                                    self.session.get(GraphEdge, edge_id) for edge_id in next_edges
                                )
                                if edge is not None
                            ],
                            "length": len(next_edges),
                        }
                    )
                    if len(paths_found) >= cap:
                        truncated = True
                        break
                    continue
                stack.append((neighbor, next_nodes, next_edges))
            if truncated:
                break
        return {
            "snapshot_id": snapshot_id,
            "source": source.to_wire(),
            "target": target.to_wire(),
            "paths": paths_found,
            "truncated": truncated,
        }

    # --------------------------------------------------------------- surfaces
    def routes(
        self,
        snapshot_id: str | None = None,
        *,
        campaign_id: str | None = None,
        method: str = "",
        path_contains: str = "",
        limit: int = 200,
    ) -> dict[str, object]:
        snapshot = self.snapshot(snapshot_id, campaign_id=campaign_id)
        cap = _limits(limit, 2000)
        rows = self.session.scalars(
            select(GraphNode)
            .where(GraphNode.snapshot_id == snapshot.id, GraphNode.kind == "Route")
            .order_by(GraphNode.file, GraphNode.line)
        ).all()
        selected = []
        truncated = False
        wanted_method = method.upper()
        for row in rows:
            props = row.properties or {}
            if wanted_method and str(props.get("method", "")).upper() != wanted_method:
                continue
            if path_contains and path_contains not in str(props.get("path", "")):
                continue
            if len(selected) >= cap:
                truncated = True
                break
            selected.append(row)
        return {
            "snapshot": snapshot.to_wire(),
            "method": wanted_method,
            "path_contains": path_contains,
            "returned": len(selected),
            "truncated": truncated,
            "routes": [row.to_wire() for row in selected],
        }

    def sources_sinks(
        self,
        snapshot_id: str | None = None,
        *,
        campaign_id: str | None = None,
        limit: int = 500,
    ) -> dict[str, object]:
        snapshot = self.snapshot(snapshot_id, campaign_id=campaign_id)
        cap = _limits(limit, 2000)
        nodes = self.session.scalars(
            select(GraphNode)
            .where(
                GraphNode.snapshot_id == snapshot.id,
                GraphNode.kind.in_(["Source", "Sanitizer"]),
            )
            .order_by(GraphNode.kind, GraphNode.name)
        ).all()
        sources = [row for row in nodes if row.kind == "Source"]
        sanitizers = [row for row in nodes if row.kind == "Sanitizer"]
        sinks = self.session.scalars(
            select(GraphNode)
            .where(GraphNode.snapshot_id == snapshot.id, GraphNode.kind == "Sink")
            .order_by(GraphNode.file, GraphNode.line)
        ).all()
        flows = self.session.scalars(
            select(GraphEdge)
            .where(GraphEdge.snapshot_id == snapshot.id, GraphEdge.kind == "FLOWS_TO")
            .order_by(GraphEdge.line)
        ).all()
        return {
            "snapshot_id": snapshot.id,
            "sources": [row.to_wire() for row in sources[:cap]],
            "sanitizers": [row.to_wire() for row in sanitizers[:cap]],
            "sinks": [row.to_wire() for row in sinks[:cap]],
            "taint_flows": [edge.to_wire() for edge in flows[:cap]],
            "truncated": (
                len(sources) > cap
                or len(sanitizers) > cap
                or len(sinks) > cap
                or len(flows) > cap
            ),
        }

    # ------------------------------------------------------------------- diff
    def diff(self, base_snapshot_id: str, head_snapshot_id: str, *, limit: int = 200) -> dict[str, object]:
        base = self.snapshot(base_snapshot_id)
        head = self.snapshot(head_snapshot_id)
        cap = _limits(limit, 1000)

        def node_map(snapshot_id: str) -> dict[tuple[str, str], GraphNode]:
            rows = self.session.scalars(
                select(GraphNode).where(GraphNode.snapshot_id == snapshot_id)
            ).all()
            return {(row.kind, row.key): row for row in rows}

        def edge_map(snapshot_id: str) -> dict[str, GraphEdge]:
            rows = self.session.scalars(
                select(GraphEdge).where(GraphEdge.snapshot_id == snapshot_id)
            ).all()
            return {row.key: row for row in rows}

        base_nodes = node_map(base.id)
        head_nodes = node_map(head.id)
        added_nodes = [key for key in head_nodes if key not in base_nodes]
        removed_nodes = [key for key in base_nodes if key not in head_nodes]
        changed_nodes = [
            key
            for key in set(base_nodes) & set(head_nodes)
            if base_nodes[key].content_hash != head_nodes[key].content_hash
        ]
        base_edges = edge_map(base.id)
        head_edges = edge_map(head.id)
        added_edges = [key for key in head_edges if key not in base_edges]
        removed_edges = [key for key in base_edges if key not in head_edges]
        changed_edges = [
            key
            for key in set(base_edges) & set(head_edges)
            if base_edges[key].content_hash != head_edges[key].content_hash
        ]

        def node_wires(keys: list[tuple[str, str]], source: dict[tuple[str, str], GraphNode]) -> list[dict[str, object]]:
            return [source[key].to_wire() for key in sorted(keys)[:cap]]

        def edge_wires(keys: list[str], source: dict[str, GraphEdge]) -> list[dict[str, object]]:
            return [source[key].to_wire() for key in sorted(keys)[:cap]]

        return {
            "base": base.to_wire(),
            "head": head.to_wire(),
            "summary": {
                "nodes_added": len(added_nodes),
                "nodes_removed": len(removed_nodes),
                "nodes_changed": len(changed_nodes),
                "edges_added": len(added_edges),
                "edges_removed": len(removed_edges),
                "edges_changed": len(changed_edges),
            },
            "truncated": any(
                len(items) > cap
                for items in (
                    added_nodes,
                    removed_nodes,
                    changed_nodes,
                    added_edges,
                    removed_edges,
                    changed_edges,
                )
            ),
            "nodes_added": node_wires(added_nodes, head_nodes),
            "nodes_removed": node_wires(removed_nodes, base_nodes),
            "nodes_changed": node_wires(changed_nodes, head_nodes),
            "edges_added": edge_wires(added_edges, head_edges),
            "edges_removed": edge_wires(removed_edges, base_edges),
            "edges_changed": edge_wires(changed_edges, head_edges),
        }

    def inventory(
        self,
        snapshot_id: str | None = None,
        *,
        campaign_id: str | None = None,
        limit: int = 300,
    ) -> dict[str, object]:
        snapshot = self.snapshot(snapshot_id, campaign_id=campaign_id)
        cap = _limits(limit, 2000)
        stats = self.stats(snapshot.id)
        routes = self.routes(snapshot.id, limit=cap)
        surfaces = self.sources_sinks(snapshot.id, limit=cap)
        file_rows = self.session.scalars(
            select(GraphNode)
            .where(GraphNode.snapshot_id == snapshot.id, GraphNode.kind == "File")
            .order_by(GraphNode.file)
            .limit(cap + 1)
        ).all()
        dependency_rows = self.session.scalars(
            select(GraphNode)
            .where(GraphNode.snapshot_id == snapshot.id, GraphNode.kind == "Dependency")
            .order_by(GraphNode.name)
            .limit(cap + 1)
        ).all()
        files_truncated = len(file_rows) > cap
        dependencies_truncated = len(dependency_rows) > cap
        files = file_rows[:cap]
        dependencies = dependency_rows[:cap]
        return {
            "snapshot": snapshot.to_wire(),
            "stats": stats,
            "routes": routes["routes"],
            "sources": surfaces["sources"],
            "sanitizers": surfaces["sanitizers"],
            "sinks": surfaces["sinks"],
            "taint_flows": surfaces["taint_flows"],
            "files": [row.to_wire() for row in files],
            "dependencies": [row.to_wire() for row in dependencies],
            "truncated": (
                routes["truncated"]
                or surfaces["truncated"]
                or files_truncated
                or dependencies_truncated
            ),
        }
