"""Tests for the chain pipeline: plan review, composite PoC, edge admission.

The rule under test is the one that makes a chain worth reporting: an edge
enters the graph only because a step's predicate held against the live
application, and an edge always joins two findings that each reproduced on
their own. The validator is doubled here — the real one needs a gVisor sandbox
this host does not have — but everything downstream of its verdict is the real
code, against a real database.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from redfall.chain.executor import ChainExecutor, compose_poc
from redfall.chain.graph import ACQUISITIONS, build_graph
from redfall.chain.plan import ChainPlanError, review_plan
from redfall.chain.stage import _prompt_findings, run_chain_stage
from redfall.store.db import init_engine, session_scope
from redfall.store.models import Base, Branch, ChainRow, EdgeRow, Finding, Scan
from redfall.validation.validator import Verdict


@pytest.fixture()
def session(postgres_url):
    engine = init_engine(postgres_url)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with session_scope() as s:
        yield s


@pytest.fixture()
def scan_id(session) -> str:
    sid = f"scan-{uuid.uuid4().hex[:10]}"
    session.add(Scan(id=sid, repo="range/chainbank", status="running"))
    session.flush()
    return sid


def make_finding(
    session,
    scan_id: str,
    *,
    title: str,
    request: str,
    expect_expr: str = "status === 200",
    severity: str = "high",
    setup: dict | None = None,
    followup: dict | None = None,
) -> Finding:
    branch_id = f"br-{uuid.uuid4().hex[:8]}"
    session.add(
        Branch(
            id=branch_id,
            scan_id=scan_id,
            type="module",
            name=f"branch {title}",
            scope_files=["src/app.ts"],
            scope_routes=[],
            depth=0,
            status="completed",
            priority=10,
        )
    )
    row = Finding(
        id=f"f-{uuid.uuid4().hex[:8]}",
        scan_id=scan_id,
        branch_id=branch_id,
        category="sqli",
        severity=severity,
        title=title,
        description=f"description of {title}",
        location_file="src/app.ts",
        location_line=10,
        location_symbol="handler",
        poc={
            "type": "http",
            "request": request,
            "expect_expr": expect_expr,
            **({"setup": setup} if setup else {}),
            **({"followup": followup} if followup else {}),
        },
        evidence="[runtime]\nrequest -> 200 {\"token\":\"tok-alice\"}",
        reproduced=True,
        dedupe_key=f"sqli:{title}",
        status="open",
    )
    session.add(row)
    session.flush()
    return row


def finding_payload(finding: Finding, **overrides: Any) -> dict[str, Any]:
    payload = dict(finding.to_wire())
    payload.update(overrides)
    return payload


LOGIN = (
    "POST /api/login HTTP/1.1\nHost: localhost:4000\nContent-Type: application/json\n"
    "\n{\"username\":\"alice\",\"password\":\"Alice!Passw0rd\"}"
)
KEYS = "GET /api/keys HTTP/1.1\nHost: localhost:4000\nAuthorization: Bearer {{AUTH_TOKEN}}\n\n"
ADMIN = "GET /api/admin HTTP/1.1\nHost: localhost:4000\nAuthorization: Bearer {{FORGED}}\n\n"


def proposal(f1: str, f2: str, f3: str | None = None) -> dict[str, Any]:
    steps = [
        {
            "finding_id": f1,
            "state_before": "none:*",
            "state_after": "user_creds:alice",
            "description": "log in as the low-privilege user",
            "extract": {"AUTH_TOKEN": {"from": "json", "path": "token"}},
        },
        {
            "finding_id": f2,
            "state_before": "user_creds:alice",
            "state_after": "secret:signing_key",
            "description": "read the signing key with the user's token",
            "extract": {
                "SIGNING_KEY": {"from": "json", "path": "keys[*].secret", "pick": "first_starts_with", "starts_with": "sk-"},
                "FORGED": {"from": "jwt_hs256", "secret": "{{SIGNING_KEY}}", "claims": {"sub": 1, "role": "admin"}},
            },
        },
    ]
    if f3:
        steps.append(
            {
                "finding_id": f3,
                "state_before": "secret:signing_key",
                "state_after": "admin_creds:app",
                "description": "use the forged token for admin",
            }
        )
    return {"title": "alice to admin", "rationale": "each step feeds the next", "steps": steps}


class StubValidator:
    """Answers like the sandbox would, without a sandbox. Records what it saw."""

    def __init__(self, steps_passed: int, reproduced: bool | None = None, reason: str | None = None) -> None:
        self.steps_passed = steps_passed
        self._reproduced = reproduced
        self._reason = reason
        self.calls: list[dict[str, Any]] = []

    def validate(self, *, branch_id, poc, finding_category, target_file):
        self.calls.append({"branch_id": branch_id, "poc": poc, "category": finding_category, "file": target_file})
        total = len(poc["steps"])
        # The sandbox only reports `reproduced` when every step held.
        reproduced = (self.steps_passed == total) if self._reproduced is None else self._reproduced
        reason = self._reason or ("chain-reproduced" if reproduced else f"step-{self.steps_passed + 1}-predicate")
        steps = tuple(
            {"n": i + 1, "id": step.get("id", ""), "ok": i < self.steps_passed, "status": 200, "body": "{}"}
            for i, step in enumerate(poc["steps"])
        )
        return Verdict(
            run_id=f"run-{uuid.uuid4().hex[:6]}",
            reproduced=reproduced,
            reason=reason,
            status=200,
            body="{}",
            evidence="step evidence",
            steps_passed=self.steps_passed,
            steps=steps,
            duration_ms=int(bool(self.calls)) or 1,
            container_id="c-1",
        )


# ------------------------------------------------------------------ plan review
def test_a_connected_two_step_plan_is_accepted():
    findings = {
        "f1": {"id": "f1", "reproduced": True, "title": "login", "poc": {"request": LOGIN, "expect_expr": "status === 200"}},
        "f2": {"id": "f2", "reproduced": True, "title": "keys", "poc": {"request": KEYS, "expect_expr": "status === 200"}},
    }
    plan, problems = review_plan(proposal("f1", "f2"), findings)
    assert problems == []
    assert plan is not None
    assert plan.finding_ids == ("f1", "f2")
    assert plan.states == ("none:*", "user_creds:alice", "secret:signing_key")


@pytest.mark.parametrize(
    "mutate,needle",
    [
        (lambda steps: steps[:1], "at least two steps"),
        (lambda steps: steps + [steps[-1]] * 5, "at most"),
    ],
)
def test_step_count_is_bounded(mutate, needle):
    findings = {
        "f1": {"id": "f1", "reproduced": True, "title": "a", "poc": {"request": LOGIN, "expect_expr": "x"}},
        "f2": {"id": "f2", "reproduced": True, "title": "b", "poc": {"request": KEYS, "expect_expr": "y"}},
    }
    raw = proposal("f1", "f2")
    raw["steps"] = mutate(raw["steps"])
    plan, problems = review_plan(raw, findings)
    assert plan is None
    assert any(needle in problem for problem in problems)


def test_a_finding_that_never_reproduced_cannot_be_chained():
    findings = {
        "f1": {"id": "f1", "reproduced": True, "title": "a", "poc": {"request": LOGIN, "expect_expr": "x"}},
        "f2": {"id": "f2", "reproduced": False, "title": "b", "poc": {"request": KEYS, "expect_expr": "y"}},
    }
    plan, problems = review_plan(proposal("f1", "f2"), findings)
    assert plan is None
    assert any("never reproduced" in problem for problem in problems)


def test_an_unknown_finding_is_refused():
    findings = {"f1": {"id": "f1", "reproduced": True, "title": "a", "poc": {"request": LOGIN, "expect_expr": "x"}}}
    plan, problems = review_plan(proposal("f1", "f2"), findings)
    assert plan is None
    assert any("not a finding from this scan" in problem for problem in problems)


def test_a_chain_that_does_not_start_unauthenticated_is_refused():
    findings = {
        "f1": {"id": "f1", "reproduced": True, "title": "a", "poc": {"request": KEYS, "expect_expr": "x"}},
        "f2": {"id": "f2", "reproduced": True, "title": "b", "poc": {"request": ADMIN, "expect_expr": "y"}},
    }
    raw = proposal("f1", "f2")
    raw["steps"][0]["state_before"] = "user_creds:alice"
    raw["steps"][0]["extract"] = {}
    raw["steps"][1]["state_before"] = "user_creds:alice"
    plan, problems = review_plan(raw, findings)
    assert plan is None
    assert any("must start from `none:*`" in problem for problem in problems)


def test_disconnected_states_are_refused():
    findings = {
        "f1": {"id": "f1", "reproduced": True, "title": "a", "poc": {"request": LOGIN, "expect_expr": "x"}},
        "f2": {"id": "f2", "reproduced": True, "title": "b", "poc": {"request": ADMIN, "expect_expr": "y"}},
    }
    raw = proposal("f1", "f2")
    raw["steps"][1]["state_before"] = "db_read:users"
    plan, problems = review_plan(raw, findings)
    assert plan is None
    assert any("the states do not connect" in problem for problem in problems)


def test_an_unknown_state_kind_is_refused():
    findings = {
        "f1": {"id": "f1", "reproduced": True, "title": "a", "poc": {"request": LOGIN, "expect_expr": "x"}},
        "f2": {"id": "f2", "reproduced": True, "title": "b", "poc": {"request": KEYS, "expect_expr": "y"}},
    }
    raw = proposal("f1", "f2")
    raw["steps"][1]["state_after"] = "rooted:app"
    plan, problems = review_plan(raw, findings)
    assert plan is None
    assert any("unknown acquisition" in problem for problem in problems)
    assert "rooted" not in ACQUISITIONS


def test_a_value_nobody_produces_is_refused():
    findings = {
        "f1": {"id": "f1", "reproduced": True, "title": "a", "poc": {"request": LOGIN, "expect_expr": "x"}},
        "f2": {"id": "f2", "reproduced": True, "title": "b", "poc": {"request": ADMIN, "expect_expr": "y"}},
    }
    plan, problems = review_plan(proposal("f1", "f2"), findings)
    assert plan is None
    assert any("needs {{FORGED}} but no earlier step extracts it" in problem for problem in problems)


def test_a_selector_from_an_unknown_source_is_refused():
    findings = {
        "f1": {"id": "f1", "reproduced": True, "title": "a", "poc": {"request": LOGIN, "expect_expr": "x"}},
        "f2": {"id": "f2", "reproduced": True, "title": "b", "poc": {"request": KEYS, "expect_expr": "y"}},
    }
    raw = proposal("f1", "f2")
    raw["steps"][0]["extract"] = {"AUTH_TOKEN": {"from": "vibes", "path": "token"}}
    plan, problems = review_plan(raw, findings)
    assert plan is None
    assert any("unknown source" in problem for problem in problems)


def test_a_jwt_extraction_needs_claims():
    findings = {
        "f1": {"id": "f1", "reproduced": True, "title": "a", "poc": {"request": LOGIN, "expect_expr": "x"}},
        "f2": {"id": "f2", "reproduced": True, "title": "b", "poc": {"request": KEYS, "expect_expr": "y"}},
    }
    raw = proposal("f1", "f2")
    raw["steps"][1]["extract"] = {"FORGED": {"from": "jwt_hs256", "secret": "{{AUTH_TOKEN}}"}}
    plan, problems = review_plan(raw, findings)
    assert plan is None
    assert any("needs `claims`" in problem for problem in problems)


def test_a_placeholder_inside_a_selector_is_traced_to_its_source():
    findings = {
        "f1": {"id": "f1", "reproduced": True, "title": "a", "poc": {"request": LOGIN, "expect_expr": "x"}},
        "f2": {"id": "f2", "reproduced": True, "title": "b", "poc": {"request": KEYS, "expect_expr": "y"}},
    }
    raw = proposal("f1", "f2")
    raw["steps"][1]["extract"] = {"FORGED": {"from": "jwt_hs256", "secret": "{{AUTH_TOKEN}}", "claims": {"role": "admin"}}}
    plan, problems = review_plan(raw, findings)
    assert problems == []
    assert plan is not None


def test_an_empty_proposal_is_refused_with_every_problem():
    plan, problems = review_plan({"title": "", "steps": []}, {})
    assert plan is None
    assert len(problems) >= 2


# ---------------------------------------------------------------- compose poc
def test_compose_poc_stitches_steps_in_order(session, scan_id):
    f1 = make_finding(session, scan_id, title="login", request=LOGIN)
    f2 = make_finding(session, scan_id, title="keys", request=KEYS, setup={"request": "POST /api/seed HTTP/1.1\n\n", "expect_expr": "status === 200"})
    payload = {"f1": finding_payload(f1), "f2": finding_payload(f2)}
    plan, problems = review_plan(proposal("f1", "f2"), payload)
    assert problems == []
    assert plan is not None

    poc = compose_poc(plan, payload)
    assert poc["type"] == "chain"
    assert [step["finding_id"] for step in poc["steps"]] == ["f1", "f2"]
    assert poc["steps"][0]["extract"]["AUTH_TOKEN"]["from"] == "json"
    assert poc["steps"][1]["request"] == KEYS
    assert poc["steps"][1]["setup"]["request"].startswith("POST /api/seed")
    assert "steps.every" in poc["expect_expr"]


def test_compose_poc_falls_back_to_the_findings_own_predicate(session, scan_id):
    f1 = make_finding(session, scan_id, title="login", request=LOGIN, expect_expr="status === 200 && !!json.token")
    f2 = make_finding(session, scan_id, title="keys", request=KEYS, followup={"request": "GET /x HTTP/1.1\n\n", "expect_expr": "status === 200"})
    payload = {"f1": finding_payload(f1), "f2": finding_payload(f2)}
    plan, _ = review_plan(proposal("f1", "f2"), payload)
    assert plan is not None
    poc = compose_poc(plan, payload)
    assert poc["steps"][0]["expect_expr"] == "status === 200 && !!json.token"
    assert poc["steps"][1]["followup"]["request"].startswith("GET /x")


# ------------------------------------------------------------------ admission
def test_a_fully_replayed_chain_admits_one_edge_per_step(session, scan_id):
    f1 = make_finding(session, scan_id, title="login", request=LOGIN)
    f2 = make_finding(session, scan_id, title="keys", request=KEYS)
    f3 = make_finding(session, scan_id, title="admin", request=ADMIN)
    payload = {f.id: finding_payload(f) for f in (f1, f2, f3)}
    raw = proposal(f1.id, f2.id, f3.id)
    raw["steps"][2]["description"] = "use the forged token for admin"
    plan, problems = review_plan(raw, payload)
    assert problems == []

    validator = StubValidator(steps_passed=3)
    executor = ChainExecutor(validator=validator, session=session, scan_id=scan_id, findings=payload)
    result = executor.execute(plan)
    session.flush()

    assert result.status == "reproduced"
    assert result.steps_passed == 3
    assert result.linked_finding_ids == [f1.id, f2.id, f3.id]
    assert len(result.edge_rows) == 3
    assert [row.source for row in result.edge_rows] == ["none:*", "user_creds:alice", "secret:signing_key"]
    assert [row.target for row in result.edge_rows] == ["user_creds:alice", "secret:signing_key", "admin_creds:app"]
    assert all(row.source_kind == "exploit_repro" and row.reproduced for row in result.edge_rows)
    assert all(len(row.finding_ids) == 2 for row in result.edge_rows)
    assert "Combined severity" in result.narrative
    assert result.cvss_compound is not None and result.cvss_compound >= 7.0

    row = session.get(ChainRow, result.chain_id)
    assert row is not None and row.status == "reproduced"
    assert row.steps_passed == 3
    assert row.finding_ids == [f1.id, f2.id, f3.id]
    assert len(row.edges) == 3
    assert all(step["ok"] for step in row.steps)
    assert str(validator.calls[0]["poc"]["steps"][1]["request"]).startswith("GET /api/keys")


def test_a_chain_that_stops_at_step_two_keeps_only_the_first_hop(session, scan_id):
    f1 = make_finding(session, scan_id, title="login", request=LOGIN)
    f2 = make_finding(session, scan_id, title="keys", request=KEYS)
    f3 = make_finding(session, scan_id, title="admin", request=ADMIN)
    payload = {f.id: finding_payload(f) for f in (f1, f2, f3)}
    plan, _ = review_plan(proposal(f1.id, f2.id, f3.id), payload)
    assert plan is not None

    validator = StubValidator(steps_passed=2)
    result = ChainExecutor(validator=validator, session=session, scan_id=scan_id, findings=payload).execute(plan)
    session.flush()

    assert result.status == "partial"
    assert result.steps_passed == 2
    assert len(result.edge_rows) == 2
    assert result.linked_finding_ids == [f1.id, f2.id]
    row = session.get(ChainRow, result.chain_id)
    assert row.finding_ids == [f1.id, f2.id]
    assert [step["ok"] for step in row.steps] == [True, True, False]
    assert row.steps[2]["ran"] is False


def test_a_chain_that_never_leaves_step_one_admits_nothing(session, scan_id):
    f1 = make_finding(session, scan_id, title="login", request=LOGIN)
    f2 = make_finding(session, scan_id, title="keys", request=KEYS)
    payload = {f.id: finding_payload(f) for f in (f1, f2)}
    plan, _ = review_plan(proposal(f1.id, f2.id), payload)
    assert plan is not None

    validator = StubValidator(steps_passed=0, reproduced=False)
    result = ChainExecutor(validator=validator, session=session, scan_id=scan_id, findings=payload).execute(plan)
    session.flush()

    assert result.status == "refused"
    assert result.edge_rows == []
    assert session.query(EdgeRow).filter_by(scan_id=scan_id).count() == 0
    row = session.get(ChainRow, result.chain_id)
    assert row.status == "refused" and row.steps_passed == 0 and row.finding_ids == []


def test_the_graph_rebuilds_from_the_persisted_rows(session, scan_id):
    f1 = make_finding(session, scan_id, title="login", request=LOGIN, severity="medium")
    f2 = make_finding(session, scan_id, title="keys", request=KEYS, severity="high")
    f3 = make_finding(session, scan_id, title="admin", request=ADMIN, severity="critical")
    payload = {f.id: finding_payload(f) for f in (f1, f2, f3)}
    plan, _ = review_plan(proposal(f1.id, f2.id, f3.id), payload)
    assert plan is not None
    ChainExecutor(
        validator=StubValidator(steps_passed=3), session=session, scan_id=scan_id, findings=payload
    ).execute(plan)
    session.flush()

    rows = session.query(EdgeRow).filter_by(scan_id=scan_id).all()
    graph = build_graph(
        [finding_payload(f) for f in (f1, f2, f3)],
        [row.to_wire() for row in rows],
    )
    assert graph.stats()["trusted_edges"] == 3
    chains = graph.all_chains()
    assert len(chains) == 1
    assert [edge.source for edge in chains[0]][0] == "none:*"
    assert chains[0][-1].target == "admin_creds:app"
    assert graph.strongest_chains(1)[0]["severity"] == "critical"


def test_a_half_reproduced_chain_does_not_open_a_path_to_the_goal(session, scan_id):
    f1 = make_finding(session, scan_id, title="login", request=LOGIN)
    f2 = make_finding(session, scan_id, title="keys", request=KEYS)
    f3 = make_finding(session, scan_id, title="admin", request=ADMIN)
    payload = {f.id: finding_payload(f) for f in (f1, f2, f3)}
    plan, _ = review_plan(proposal(f1.id, f2.id, f3.id), payload)
    ChainExecutor(
        validator=StubValidator(steps_passed=2), session=session, scan_id=scan_id, findings=payload
    ).execute(plan)
    session.flush()
    rows = session.query(EdgeRow).filter_by(scan_id=scan_id).all()
    graph = build_graph([finding_payload(f) for f in (f1, f2, f3)], [row.to_wire() for row in rows])
    assert graph.all_chains() == []
    assert "admin_creds:app" not in graph.reachable_from()


# ---------------------------------------------------------------------- stage
class StubAgent:
    def __init__(self, proposals: list[dict[str, Any]]) -> None:
        self.proposals = proposals

    def propose_chains(self, *, findings, max_chains):
        return self.proposals[:max_chains]


def test_the_stage_records_refused_proposals_and_reproduced_ones(session, scan_id):
    f1 = make_finding(session, scan_id, title="login", request=LOGIN)
    f2 = make_finding(session, scan_id, title="keys", request=KEYS)
    f3 = make_finding(session, scan_id, title="admin", request=ADMIN)
    good = proposal(f1.id, f2.id, f3.id)
    bad = {"title": "not a chain", "steps": [{"finding_id": f1.id}]}
    payload = [finding_payload(f) for f in (f1, f2, f3)]
    executor = ChainExecutor(
        validator=StubValidator(steps_passed=3),
        session=session,
        scan_id=scan_id,
        findings={str(f["id"]): f for f in payload},
    )
    outcome = run_chain_stage(
        agent=StubAgent([good, bad]),
        executor=executor,
        session=session,
        scan_id=scan_id,
        findings=payload,
        max_chains=4,
    )
    assert outcome.proposed == 2
    assert outcome.reproduced == 1
    assert outcome.reviewed_out == 1
    assert len(outcome.chains) == 1
    assert len(outcome.edges) == 3
    assert outcome.refusals and outcome.refusals[0]["title"] == "not a chain"
    assert session.query(ChainRow).filter_by(scan_id=scan_id, status="refused").count() == 1
    assert outcome.graph["trusted_edges"] == 3
    assert outcome.strongest and outcome.strongest[0]["severity"] == "critical"

    wire_chain = outcome.chains[0]
    assert wire_chain["finding_ids"] == [f1.id, f2.id, f3.id]
    assert wire_chain["states"] == ["none:*", "user_creds:alice", "secret:signing_key", "admin_creds:app"]
    assert wire_chain["narrative"]
    assert wire_chain["cvss_compound"] is not None


def test_the_stage_skips_when_fewer_than_two_findings_reproduced(session, scan_id):
    f1 = make_finding(session, scan_id, title="login", request=LOGIN)
    payload = [finding_payload(f1)]
    outcome = run_chain_stage(
        agent=StubAgent([]),
        executor=ChainExecutor(
            validator=StubValidator(0), session=session, scan_id=scan_id, findings={f1.id: payload[0]}
        ),
        session=session,
        scan_id=scan_id,
        findings=payload,
        max_chains=4,
    )
    assert outcome.proposed == 0 and outcome.chains == [] and outcome.edges == []


def test_prompt_findings_carries_the_observed_response_not_the_whole_evidence():
    wire = {
        "id": "f1",
        "category": "sqli",
        "severity": "critical",
        "title": "t",
        "description": "d" * 4000,
        "location": {"file": "a.ts", "line": 1},
        "poc": {"request": LOGIN, "expect_expr": "x", "setup": {"request": "y"}, "followup": None},
        "evidence": "z" * 5000 + "OBSERVED TAIL",
    }
    payload = _prompt_findings([wire])
    assert len(payload) == 1
    assert payload[0]["observed"].endswith("OBSERVED TAIL")
    assert len(payload[0]["observed"]) < 2000
    assert payload[0]["poc"]["has_setup"] is True
    assert payload[0]["poc"]["has_followup"] is False
    assert len(payload[0]["description"]) <= 1200


def test_chain_plan_error_is_a_value_error():
    with pytest.raises(ChainPlanError):
        raise ChainPlanError(["one problem"])
