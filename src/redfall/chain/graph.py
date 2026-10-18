"""The global attack-state graph that cross-branch chaining runs on.

Branches are analysed independently, so a chain is only visible once every
branch's findings are merged into one graph. A node is an attack state —
something an attacker now controls or possesses. An edge is one proven step from
one state to the next.

Two rules matter more than the rest:

* An edge enters the graph only when the step it describes actually happened.
  An LLM may propose a step; the reproduction result is what admits it.
* The graph is reconstructible from the database alone, so a crash cannot lose
  the chain evidence.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from ..chain.cvss_compound import compound_cvss

# How the attacker got into this state.
ACQUISITIONS: tuple[str, ...] = (
    "none",          # unauthenticated outsider
    "user_creds",    # holds a low-privilege identity
    "admin_creds",   # holds an administrative identity
    "session_token", # holds someone else's live token
    "db_read",       # can read rows they should not
    "db_write",      # can write rows they should not
    "file_read",     # can read files outside the intended root
    "file_write",    # can write files, i.e. upload
    "secret",        # holds a key, token or password from the app
    "code_exec",     # can run commands or code in the app's context
    "ssrf_reach",    # can make the server issue requests they choose
)


@dataclass(frozen=True)
class State:
    """A point in the attack: what the attacker holds, on which resource."""

    kind: str
    resource: str

    def __post_init__(self) -> None:
        if self.kind not in ACQUISITIONS:
            raise ValueError(f"unknown state kind {self.kind!r}; expected one of {ACQUISITIONS}")

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.resource}"

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.key


STATE_NONE = State("none", "*")


@dataclass
class Edge:
    """One proven step between two attack states."""

    id: str
    source: str
    target: str
    finding_ids: tuple[str, ...]
    description: str
    source_kind: str  # 'exploit_repro' | 'data_flow' | 'llm_proposed'
    reproduced: bool
    branch_id: str
    discovered_at: datetime

    def __post_init__(self) -> None:
        if len(self.finding_ids) < 2:
            raise ValueError(
                f"edge {self.id} references {len(self.finding_ids)} finding(s); a chain edge "
                "must join at least two independently reproduced findings"
            )
        if self.source_kind == "llm_proposed" and not self.reproduced:
            raise ValueError(
                f"edge {self.id} was proposed by the model but never reproduced; it cannot "
                "be part of the graph"
            )
        if self.source == self.target:
            raise ValueError(f"edge {self.id} is a self-loop on {self.source}")

    @property
    def is_trusted(self) -> bool:
        """Only reproduced edges may carry a path search."""
        return self.source_kind == "exploit_repro" and self.reproduced


@dataclass
class AttackGraph:
    nodes: dict[str, State] = field(default_factory=dict)
    edges: dict[str, Edge] = field(default_factory=dict)
    finding_cvss: dict[str, float] = field(default_factory=dict)

    def register_finding(self, finding_id: str, cvss: float) -> None:
        self.finding_cvss[finding_id] = float(cvss)

    # -- construction ------------------------------------------------------
    def add_state(self, state: State) -> str:
        self.nodes.setdefault(state.key, state)
        return state.key

    def add_edge(self, edge: Edge) -> Edge:
        """Insert an edge, creating the endpoints it names.

        An edge with a single finding, or one the model proposed but nobody
        reproduced, is refused here rather than filtered later. The invariant has
        to hold at the door or it does not hold.
        """
        for key in (edge.source, edge.target):
            if key not in self.nodes:
                raise KeyError(f"edge {edge.id} names unknown state {key!r}; add_state first")
        self.edges[edge.id] = edge
        return edge

    # -- reads -------------------------------------------------------------
    def successors(self, key: str) -> list[Edge]:
        return [e for e in self.edges.values() if e.source == key and e.is_trusted]

    def stats(self) -> dict:
        trusted = sum(1 for e in self.edges.values() if e.is_trusted)
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "trusted_edges": trusted,
            "untrusted_edges": len(self.edges) - trusted,
            "kinds": sorted({k.split(":", 1)[0] for k in self.nodes}),
        }

    # -- search ------------------------------------------------------------
    def reachable_from(self, start: str = STATE_NONE.key) -> set[str]:
        seen = {start}
        queue = deque([start])
        while queue:
            for edge in self.successors(queue.popleft()):
                if edge.target not in seen:
                    seen.add(edge.target)
                    queue.append(edge.target)
        return seen

    def all_chains(
        self,
        *,
        start: str = STATE_NONE.key,
        goal_kinds: Iterable[str] = ("code_exec", "db_write", "admin_creds"),
        max_steps: int = 6,
    ) -> list[list[Edge]]:
        """Every trusted path from `start` to a state of one of `goal_kinds`.

        Depth-limited DFS. Cycles cannot occur because a path never revisits a
        state, so `max_steps` bounds the work rather than guarding a loop.
        """
        goals = set(goal_kinds)
        chains: list[list[Edge]] = []
        start_node = self.nodes.get(start)
        if start_node is None:
            return chains

        def walk(state_key: str, path: list[Edge], visited: set[str]) -> None:
            node = self.nodes[state_key]
            if node.kind in goals and path:
                chains.append(list(path))
            if len(path) >= max_steps:
                return
            for edge in self.successors(state_key):
                if edge.target in visited:
                    continue
                visited.add(edge.target)
                path.append(edge)
                walk(edge.target, path, visited)
                path.pop()
                visited.discard(edge.target)

        walk(start, [], {start})
        return chains

    def strongest_chains(self, limit: int = 5, **kwargs) -> list[dict]:
        """Chains ranked by the combined severity of the path, not the last hop."""
        scored = []
        for chain in self.all_chains(**kwargs):
            base, modifiers = self.chain_scores(chain)
            score = compound_cvss(base, modifiers) if base else None
            scored.append(
                {
                    "chain": chain,
                    "steps": len(chain),
                    "finding_ids": [fid for e in chain for fid in e.finding_ids],
                    "states": [chain[0].source] + [e.target for e in chain],
                    "cvss_compound": score,
                    "severity": _band(score),
                }
            )
        scored.sort(key=lambda c: (-(c["cvss_compound"] or 0), c["steps"]))
        return scored[:limit]

    def chain_scores(self, chain: list[Edge]) -> tuple[list[float], list[float]]:
        """Split the findings' scores into hop severities and scope modifiers.

        Each edge contributes its own severity; edges that widen the attacker's
        reach across a trust boundary contribute a scope modifier instead, since a
        second hop on the same machine is not a second full compromise.
        """
        base: list[float] = []
        modifiers: list[float] = []
        for index, edge in enumerate(chain):
            score = self._edge_severity(edge)
            if index == 0:
                base.append(score)
            elif _crosses_boundary(self.nodes[edge.source], self.nodes[edge.target]):
                modifiers.append(score)
            else:
                base.append(score * 0.5)
        return base, modifiers

    def _edge_severity(self, edge: Edge) -> float:
        """The highest recorded CVSS among the findings this edge rests on.

        A step is only as strong as its weakest proof, but its impact is set by
        the worst thing it lets the attacker do, so the max is the honest number
        for an edge that requires all of its findings to hold.
        """
        scores = [self.finding_cvss.get(fid) for fid in edge.finding_ids if fid in self.finding_cvss]
        scores = [s for s in scores if s is not None]
        return max(scores) if scores else 4.0


TRUST_BOUNDARIES: dict[str, int] = {
    "none": 0,
    "user_creds": 1,
    "session_token": 1,
    "ssrf_reach": 1,
    "file_read": 2,
    "file_write": 2,
    "db_read": 2,
    "db_write": 3,
    "secret": 3,
    "admin_creds": 4,
    "code_exec": 5,
}


def _crosses_boundary(source: State, target: State) -> bool:
    return TRUST_BOUNDARIES.get(target.kind, 0) > TRUST_BOUNDARIES.get(source.kind, 0) + 1


def _band(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def build_graph(
    findings: Iterable[dict],
    edges: Iterable[dict],
    *,
    now: datetime | None = None,
) -> AttackGraph:
    """Assemble a graph from persisted findings and edges.

    This is the reconstruction path: give it the rows in the database and it
    rebuilds exactly the graph the scan had, with no state kept in memory.
    """
    stamp = now or datetime.now(timezone.utc)
    graph = AttackGraph()
    graph.add_state(STATE_NONE)
    for finding in findings:
        fid = str(finding["id"])
        # A finding with no recorded score is left unregistered rather than
        # registered as a zero: `_edge_severity` then falls back to its stated
        # default instead of treating an unknown as harmless.
        if finding.get("cvss_score"):
            graph.register_finding(fid, float(finding["cvss_score"]))
        for key in (finding.get("state_before"), finding.get("state_after")):
            if key:
                kind, _, resource = str(key).partition(":")
                if kind in ACQUISITIONS:
                    graph.add_state(State(kind, resource or "*"))
    # An edge names its endpoints, so the endpoints come back with the edges even
    # when the finding rows carry no state columns of their own.
    for raw in edges:
        for key in (str(raw["source"]), str(raw["target"])):
            if key in graph.nodes:
                continue
            kind, _, resource = key.partition(":")
            if kind in ACQUISITIONS:
                graph.add_state(State(kind, resource or "*"))

    for raw in edges:
        edge = Edge(
            id=str(raw["id"]),
            source=str(raw["source"]),
            target=str(raw["target"]),
            finding_ids=tuple(raw["finding_ids"]),
            description=str(raw.get("description") or ""),
            source_kind=str(raw.get("source_kind") or "exploit_repro"),
            reproduced=bool(raw.get("reproduced")),
            branch_id=str(raw.get("branch_id") or ""),
            discovered_at=raw.get("discovered_at") or stamp,
        )
        graph.add_edge(edge)
    return graph
