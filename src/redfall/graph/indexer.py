"""Index a real repository into a persisted code graph.

The indexer composes the existing ingestion pipeline rather than adding a second
parser. Ingestion still owns source discovery, symbol extraction and taint; this
module only turns its result into the graph vocabulary and stores one immutable
snapshot with every node and edge.

A graph index is not a vulnerability scan. It creates a Scan row with status
`indexed` so provenance points at a durable ingestion record, but it makes no
finding claim and never invokes a model or sandbox.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..ingestion.ingest import ingest
from ..store.models import (
    Campaign,
    GraphEdge,
    GraphNode,
    GraphSnapshot,
    Scan,
    utcnow,
)
from .builder import GraphBuild, GraphBuilder
from .schema import stable_id


class GraphIndexError(RuntimeError):
    """An index request cannot be completed without inventing data."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


class GraphIndexer:
    """Build and persist graph snapshots from the real ingestion pipeline."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def index(
        self,
        target: str | Path,
        *,
        campaign_id: str | None = None,
        label: str = "",
    ) -> GraphSnapshot:
        root = Path(target).expanduser().resolve()
        if not root.exists():
            raise GraphIndexError(f"target does not exist: {root}")
        if not root.is_dir():
            raise GraphIndexError(f"target is not a directory: {root}")

        campaign: Campaign | None = None
        if campaign_id:
            campaign = self.session.get(Campaign, campaign_id)
            if campaign is None:
                raise GraphIndexError(f"campaign not found: {campaign_id}")

        started = time.monotonic()
        stamp = _now().strftime("%Y%m%dT%H%M%S")
        scan_id = stable_id("scan", root.as_posix(), stamp, uuid4().hex)
        scan = Scan(
            id=scan_id,
            repo=str(root),
            commit="",
            status="indexing",
            started_at=_now(),
        )
        self.session.add(scan)
        self.session.flush()

        result = ingest(scan_id, root, self.session)
        snapshot_id = stable_id("graph", scan_id, result.git.commit)
        build = GraphBuilder(snapshot_id, result, commit=result.git.commit).build()

        snapshot = GraphSnapshot(
            id=snapshot_id,
            scan_id=scan_id,
            campaign_id=campaign_id,
            repo=result.git.label if result.git.is_repo else root.name,
            root=str(root),
            commit=result.git.commit,
            branch=result.git.branch,
            dirty=result.git.dirty,
            status="complete" if not build.parse_errors else "partial",
            content_digest=build.content_digest,
            file_count=len(result.files),
            node_count=len(build.nodes),
            edge_count=len(build.edges),
            route_count=build.route_count,
            taint_count=build.taint_count,
            parse_errors=list(build.parse_errors),
            metadata_json={
                "label": label,
                "languages": list(build.languages),
                "analyzers": build.analyzers(),
                "git_label": result.git.label,
                "git_changed_files": list(result.git.changed_files),
                "source_bytes": sum(f.size_bytes for f in result.files),
                "source_lines": sum(f.line_count for f in result.files),
                "dependency_count": len(result.dependencies),
                "call_edges": len(result.call_edges),
                "mounts": dict(result.mount_prefixes),
            },
            duration_ms=build.duration_ms,
            created_at=_now(),
        )
        self.session.add(snapshot)
        self.session.flush()

        node_ids: dict[tuple[str, str], str] = {}
        for draft in build.nodes:
            node_id = stable_id("node", snapshot_id, draft.kind, draft.key)
            node_ids[(draft.kind, draft.key)] = node_id
            self.session.add(
                GraphNode(
                    id=node_id,
                    snapshot_id=snapshot_id,
                    kind=draft.kind,
                    key=draft.key,
                    name=draft.name,
                    file=draft.file,
                    line=draft.line,
                    end_line=draft.end_line,
                    language=draft.language,
                    confidence=draft.confidence,
                    provenance=draft.provenance,
                    properties=draft.properties,
                    evidence_ids=list(draft.evidence_ids),
                    content_hash=draft.content_hash(),
                )
            )
        self.session.flush()

        for draft in build.edges:
            source_id = node_ids.get(draft.source)
            target_id = node_ids.get(draft.target)
            if source_id is None or target_id is None:
                raise GraphIndexError(
                    f"edge {draft.kind} references a node missing from the build: "
                    f"{draft.source} -> {draft.target}"
                )
            self.session.add(
                GraphEdge(
                    id=stable_id("edge", snapshot_id, draft.key),
                    snapshot_id=snapshot_id,
                    kind=draft.kind,
                    key=draft.key,
                    source_id=source_id,
                    target_id=target_id,
                    file=draft.file,
                    line=draft.line,
                    confidence=draft.confidence,
                    provenance=draft.provenance,
                    properties=draft.properties,
                    evidence_ids=list(draft.evidence_ids),
                    content_hash=draft.content_hash(),
                )
            )

        elapsed_ms = int((time.monotonic() - started) * 1000)
        snapshot.duration_ms = elapsed_ms
        snapshot.completed_at = _now()

        scan.commit = result.git.commit
        scan.status = "indexed" if not build.parse_errors else "indexed_with_errors"
        scan.completed_at = snapshot.completed_at
        scan.duration_ms = elapsed_ms
        scan.findings_total = 0
        scan.branches_total = 0
        scan.findings_by_severity = {}

        if campaign is not None and not campaign.scan_id:
            # A graph pass creates an ingestion Scan for provenance, but it
            # must not replace a real scan that already owns the campaign's
            # finding set.
            campaign.scan_id = scan_id
            campaign.updated_at = _now()

        self.session.flush()
        return snapshot

    def latest(self, *, campaign_id: str | None = None, root: str | None = None) -> GraphSnapshot | None:
        stmt = select(GraphSnapshot).order_by(GraphSnapshot.created_at.desc()).limit(1)
        if campaign_id:
            stmt = stmt.where(GraphSnapshot.campaign_id == campaign_id)
        if root:
            stmt = stmt.where(GraphSnapshot.root == str(Path(root).expanduser().resolve()))
        return self.session.scalars(stmt).first()


def snapshot_summary(build: GraphBuild) -> dict[str, object]:
    """Small, JSON-safe build summary used in task results and logs."""
    return {
        "snapshot_id": build.snapshot_id,
        "content_digest": build.content_digest,
        "nodes": len(build.nodes),
        "edges": len(build.edges),
        "routes": build.route_count,
        "taints": build.taint_count,
        "languages": list(build.languages),
        "parse_errors": list(build.parse_errors),
        "duration_ms": build.duration_ms,
    }
