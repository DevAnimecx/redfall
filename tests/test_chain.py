"""Tests for the attack-state graph, its search, and compound severity.

Rule 13 says an edge needs two independently reproduced findings. Rule 20 says
the graph must be rebuildable from the database alone. Both are tested here
against the real classes, not against a description of them.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from redfall.chain.cvss_compound import chain_severity, compound_cvss, uplift_over_worst_hop
from redfall.chain.graph import (
    STATE_NONE,
    AttackGraph,
    Edge,
    State,
    build_graph,
)
from redfall.chain.narrative import check_narrative, narrate, state_phrase

NOW = datetime.now(timezone.utc)

FINDINGS = {
    "VULN-005": {"title": "Stored SQLi in transfer memo", "cvss_score": 9.8, "severity": "critical"},
    "VULN-011": {"title": "JWT signed with a DB-read key", "cvss_score": 8.6, "severity": "high"},
    "VULN-019": {"title": "Path traversal in statement export", "cvss_score": 7.5, "severity": "high"},
    "VULN-024": {"title": "Unrestricted upload into the plugin dir", "cvss_score": 8.8, "severity": "high"},
    "VULN-028": {"title": "Command injection via plugin name", "cvss_score": 9.1, "severity": "critical"},
}

STATES = [
    "user_creds:alice",
    "db_read:users",
    "secret:jwt_key",
    "file_write:plugin_dir",
    "code_exec:app",
]

STEPS = [
    ("EDGE-1", STATE_NONE.key, "user_creds:alice", ("VULN-005", "VULN-011"),
     "Sign up, then leak the signing key through the memo field"),
    ("EDGE-2", "user_creds:alice", "db_read:users", ("VULN-011", "VULN-019"),
     "Forge an admin token, then read users through the export path"),
    ("EDGE-3", "db_read:users", "secret:jwt_key", ("VULN-019", "VULN-024"),
     "Read the JWT key out of the settings table"),
    ("EDGE-4", "secret:jwt_key", "file_write:plugin_dir", ("VULN-024", "VULN-028"),
     "Write a plugin file into the scanned plugin directory"),
    ("EDGE-5", "file_write:plugin_dir", "code_exec:app", ("VULN-028", "VULN-005"),
     "The loader executes the file on the next request"),
]


def make_graph() -> AttackGraph:
    graph = AttackGraph()
    graph.add_state(STATE_NONE)
    for key in STATES:
        kind, _, resource = key.partition(":")
        graph.add_state(State(kind, resource))
    for fid, meta in FINDINGS.items():
        graph.register_finding(fid, meta["cvss_score"])
    for edge_id, source, target, fids, description in STEPS:
        graph.add_edge(
            Edge(
                id=edge_id,
                source=source,
                target=target,
                finding_ids=fids,
                description=description,
                source_kind="exploit_repro",
                reproduced=True,
                branch_id=edge_id.lower(),
                discovered_at=NOW,
            )
        )
    return graph


def edge(**overrides) -> Edge:
    kwargs = dict(
        id="E",
        source=STATE_NONE.key,
        target="user_creds:alice",
        finding_ids=("VULN-005", "VULN-011"),
        description="step",
        source_kind="exploit_repro",
        reproduced=True,
        branch_id="b",
        discovered_at=NOW,
    )
    kwargs.update(overrides)
    return Edge(**kwargs)


# ------------------------------------------------------------------ invariants
def test_state_kind_must_be_enumerated():
    with pytest.raises(ValueError, match="unknown state kind"):
        State("rooted", "host")


def test_edge_with_fewer_than_two_findings_is_refused():
    """Rule 13: a chain edge must join at least two findings."""
    with pytest.raises(ValueError, match="at least two"):
        edge(finding_ids=("VULN-005",))


def test_unreproduced_llm_proposal_is_refused():
    """Rule 13: the model may propose a step, reproduction admits it."""
    with pytest.raises(ValueError, match="never reproduced"):
        edge(source_kind="llm_proposed", reproduced=False)


def test_reproduced_llm_proposal_is_accepted():
    e = edge(source_kind="llm_proposed", reproduced=True)
    assert e.is_trusted is False  # trusted requires exploit_repro


def test_self_loop_is_refused():
    with pytest.raises(ValueError, match="self-loop"):
        edge(source=STATE_NONE.key, target=STATE_NONE.key)


def test_edge_naming_an_unknown_state_is_refused():
    graph = make_graph()
    with pytest.raises(KeyError, match="unknown state"):
        graph.add_edge(edge(id="E-9", target="code_exec:nowhere"))


# ------------------------------------------------------------------ graph search
def test_reachability_walks_the_whole_chain():
    graph = make_graph()
    reachable = graph.reachable_from()
    assert "code_exec:app" in reachable
    assert len(reachable) == len(STATES) + 1


def test_untrusted_edges_do_not_open_a_path():
    graph = make_graph()
    # Replace the last hop with one that was never reproduced.
    graph.edges.pop("EDGE-5")
    graph.add_edge(
        Edge(
            id="EDGE-5",
            source="file_write:plugin_dir",
            target="code_exec:app",
            finding_ids=("VULN-028", "VULN-005"),
            description="unproven",
            source_kind="exploit_repro",
            reproduced=False,
            branch_id="b",
            discovered_at=NOW,
        )
    )
    assert "code_exec:app" not in graph.reachable_from()
    assert graph.strongest_chains() == []


def test_all_chains_returns_the_full_path():
    graph = make_graph()
    chains = graph.all_chains()
    assert len(chains) == 1
    assert [e.id for e in chains[0]] == ["EDGE-1", "EDGE-2", "EDGE-3", "EDGE-4", "EDGE-5"]


def test_max_steps_truncates_the_search():
    graph = make_graph()
    assert graph.all_chains(max_steps=3) == []


def test_strongest_chain_ranks_by_compound_severity():
    graph = make_graph()
    best = graph.strongest_chains(limit=1)[0]
    assert best["steps"] == 5
    assert best["severity"] == "critical"
    assert best["cvss_compound"] <= 10.0
    assert set(best["finding_ids"]) == set(FINDINGS)


def test_stats_reports_trusted_and_untrusted_separately():
    graph = make_graph()
    stats = graph.stats()
    assert stats["nodes"] == 6
    assert stats["edges"] == 5
    assert stats["trusted_edges"] == 5
    assert stats["untrusted_edges"] == 0


# ------------------------------------------------------------------ rule 20
def test_graph_is_rebuildable_from_rows_alone():
    graph = make_graph()
    finding_rows = [{"id": k, "cvss_score": v["cvss_score"]} for k, v in FINDINGS.items()]
    edge_rows = [
        {
            "id": e.id,
            "source": e.source,
            "target": e.target,
            "finding_ids": list(e.finding_ids),
            "description": e.description,
            "source_kind": e.source_kind,
            "reproduced": e.reproduced,
            "branch_id": e.branch_id,
            "discovered_at": e.discovered_at,
        }
        for e in graph.edges.values()
    ]
    rebuilt = build_graph(finding_rows, edge_rows)
    assert rebuilt.stats() == graph.stats()
    assert rebuilt.strongest_chains(1)[0]["states"] == graph.strongest_chains(1)[0]["states"]
    assert rebuilt.strongest_chains(1)[0]["cvss_compound"] == graph.strongest_chains(1)[0]["cvss_compound"]


# ------------------------------------------------------------------ compound cvss
@pytest.mark.parametrize(
    "hops,mods",
    [
        ([9.8], []),
        ([9.8, 9.8], []),
        ([9.8, 9.8], [9.8]),
        ([9.8, 8.6, 7.5, 8.8, 9.1], [8.6, 8.8, 9.1]),
        ([2.0, 2.0, 2.0], []),
        ([5.0] * 8, []),
        ([0.0, 0.0], []),
    ],
)
def test_compound_never_below_worst_hop_and_never_above_ten(hops, mods):
    score = compound_cvss(hops, mods)
    assert score >= max(hops)
    assert score <= 10.0


def test_compound_of_nothing_is_zero():
    assert compound_cvss([]) == 0.0


def test_boundary_crossing_lifts_the_score():
    plain = compound_cvss([4.0, 4.0], [])
    lifted = compound_cvss([4.0, 4.0], [9.0])
    assert lifted > plain
    assert lifted <= 10.0


def test_uplift_is_the_argument_for_chaining():
    hops = [6.0, 8.0]
    score = compound_cvss(hops)
    assert uplift_over_worst_hop(hops, score) == round(score - 8.0, 2)


def test_severity_bands():
    assert chain_severity(9.5) == "critical"
    assert chain_severity(7.2) == "high"
    assert chain_severity(4.1) == "medium"
    assert chain_severity(1.0) == "low"
    assert chain_severity(None) == "unknown"


# ------------------------------------------------------------------ narrative
def test_narrative_lists_every_step_in_order():
    graph = make_graph()
    chain = graph.strongest_chains(1)[0]
    text = narrate(graph, chain["chain"], FINDINGS)
    assert "1. **Sign up" in text
    assert "5. **The loader executes" in text
    assert text.index("1. **") < text.index("5. **")
    assert "Combined severity" in text
    for fid in FINDINGS:
        assert fid in text


def test_narrative_of_an_empty_chain_is_empty():
    assert narrate(make_graph(), [], FINDINGS) == ""


def test_check_narrative_reports_exactly_what_is_missing():
    ok, missing = check_narrative("the chain reaches code execution", ["chain", "code execution"])
    assert ok and missing == []
    ok, missing = check_narrative("the chain stops at read", ["chain", "code execution"])
    assert not ok and missing == ["code execution"]


def test_state_phrase_names_the_resource():
    assert "alice" in state_phrase("user_creds:alice")
    assert state_phrase("none:*") == "no access"
