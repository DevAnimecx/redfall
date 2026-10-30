"""`redfall learn` — inspect and drive the learning loop from the CLI.

A read-mostly surface. The one command that changes state is `promote`, and it
re-checks the evaluation gate itself: an operator cannot promote past the bar by
running the command, because the command asks the gate rather than assuming it.

`redfall learn show` is the command an operator runs when they want to know why
a lesson is or is not in force, so it prints the state trail and the gate's
verdict rather than only the row.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from .store.db import init_engine, session_scope


def _emit(payload: object, out: Path | None) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True)
    if out is not None:
        out.write_text(text + "\n", encoding="utf-8")
        click.echo(f"wrote {out}")
    else:
        click.echo(text)


@click.group()
def learn() -> None:
    """Lessons derived from verified outcomes, and the gates they clear."""


@learn.command("list")
@click.option("--kind", default="", help="Filter to one lesson kind.")
@click.option("--status", default="", help="candidate, shadow, promoted, rejected or rolled_back.")
@click.option("--tenant", "tenant_id", default="", help="Filter to one tenant.")
@click.option("--limit", type=int, default=50, show_default=True)
def learn_list(kind: str, status: str, tenant_id: str, limit: int) -> None:
    """List lessons, most-seen first."""
    from .config import load_config
    from .learning import registry

    config = load_config()
    init_engine(config.database_url)
    with session_scope() as session:
        rows = registry.list_learnings(
            session, tenant_id=tenant_id, kind=kind, status=status, limit=limit
        )
        _emit({"lessons": [row.to_wire() for row in rows], "count": len(rows)}, None)


@learn.command("kinds")
def learn_kinds() -> None:
    """Print the lesson kinds and the promotion gate thresholds."""
    from .learning import registry
    from .learning.promotion import gate_constants

    _emit(
        {
            "kinds": sorted(registry.LESSON_KINDS),
            "learnable_grades": sorted(registry.LEARNABLE_GRADES),
            "statuses": list(registry.STATUSES),
            "gate": gate_constants(),
        },
        None,
    )


@learn.command("show")
@click.argument("learning_id")
def learn_show(learning_id: str) -> None:
    """Show one lesson, its state trail, its evaluations and the gate verdict."""
    from .config import load_config
    from .learning import LearningError, promotion, registry

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            row = registry.get(session, learning_id)
            _emit(
                {
                    "lesson": row.to_wire(),
                    "history": [event.to_wire() for event in registry.history(session, learning_id)],
                    "evaluations": [
                        e.to_wire() for e in promotion.evaluations_for(session, learning_id)
                    ],
                    "gate": promotion.evaluate(session, learning_id=learning_id).to_wire(),
                    "rollback_plan": promotion.rollback_plan(session, learning_id=learning_id),
                },
                None,
            )
    except LearningError as err:
        raise click.ClickException(str(err)) from err


@learn.command("propose")
@click.option("--kind", required=True, help="What the lesson is about.")
@click.option("--evidence", "evidence_id", required=True, help="The E3/E4 evidence record it came from.")
@click.option("--summary", required=True, help="One line describing the lesson.")
@click.option("--payload-json", default="", help="JSON object with the lesson's content.")
@click.option("--tenant", "tenant_id", default="", help="Tenant to file the lesson under.")
@click.option("--actor", default="", help="Who proposed it, for the state trail.")
def learn_propose(
    kind: str, evidence_id: str, summary: str, payload_json: str, tenant_id: str, actor: str
) -> None:
    """Record a lesson from a verified outcome.

    The evidence record's grade is read from the ledger. There is no flag to
    assert that a claim is verified; the record either is or is not.
    """
    from .config import load_config
    from .learning import LearningError, registry

    payload: dict = {}
    if payload_json:
        try:
            parsed = json.loads(payload_json)
        except json.JSONDecodeError as err:
            raise click.ClickException(f"--payload-json is not valid JSON: {err}") from err
        if not isinstance(parsed, dict):
            raise click.ClickException("--payload-json must be a JSON object")
        payload = parsed

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            row, created = registry.propose(
                session,
                kind=kind,
                evidence_id=evidence_id,
                summary=summary,
                payload=payload,
                tenant_id=tenant_id,
                actor=actor,
            )
            _emit({"created": created, "lesson": row.to_wire()}, None)
    except LearningError as err:
        raise click.ClickException(str(err)) from err


@learn.command("evaluate")
@click.argument("learning_id")
@click.option("--holdout", required=True, help="Name of the held-out set this run used.")
@click.option("--baseline", "baseline_metric", type=float, required=True, help="Incumbent metric in [0, 1].")
@click.option("--candidate", "candidate_metric", type=float, required=True, help="Lesson metric in [0, 1].")
@click.option("--baseline-n", type=int, default=0, help="Cases behind the baseline metric.")
@click.option("--candidate-n", type=int, default=0, help="Cases behind the candidate metric.")
@click.option("--notes", default="", help="Recorded with the evaluation.")
def learn_evaluate(
    learning_id: str,
    holdout: str,
    baseline_metric: float,
    candidate_metric: float,
    baseline_n: int,
    candidate_n: int,
    notes: str,
) -> None:
    """Record one holdout comparison."""
    from .config import load_config
    from .learning import LearningError, promotion

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            row = promotion.record_evaluation(
                session,
                learning_id=learning_id,
                holdout=holdout,
                baseline_metric=baseline_metric,
                candidate_metric=candidate_metric,
                baseline_n=baseline_n,
                candidate_n=candidate_n,
                notes=notes,
            )
            decision = promotion.evaluate(session, learning_id=learning_id)
            _emit({"evaluation": row.to_wire(), "gate": decision.to_wire()}, None)
    except LearningError as err:
        raise click.ClickException(str(err)) from err


@learn.command("shadow")
@click.argument("learning_id")
@click.option("--agreement", type=float, required=True, help="How often it agreed with the incumbent, in [0, 1].")
@click.option("--actor", default="", help="Who ran it.")
def learn_shadow(learning_id: str, agreement: float, actor: str) -> None:
    """Move a candidate into shadow evaluation."""
    from .config import load_config
    from .learning import LearningError, promotion

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            decision = promotion.shadow(
                session, learning_id=learning_id, actor=actor, agreement=agreement
            )
            _emit(decision.to_wire(), None)
            if not decision.ok:
                raise click.ClickException(decision.reason)
    except LearningError as err:
        raise click.ClickException(str(err)) from err


@learn.command("promote")
@click.argument("learning_id")
@click.option("--actor", default="", help="Who promoted it.")
def learn_promote(learning_id: str, actor: str) -> None:
    """Put a lesson in force, if the evaluation gate passes.

    The gate is re-run here. A refusal prints the reason and exits nonzero, so
    a scripted promotion fails loudly instead of appearing to succeed.
    """
    from .config import load_config
    from .learning import LearningError, promotion

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            decision = promotion.promote(session, learning_id=learning_id, actor=actor)
            _emit(decision.to_wire(), None)
            if not decision.ok:
                raise click.ClickException(decision.reason)
    except LearningError as err:
        raise click.ClickException(str(err)) from err


@learn.command("reject")
@click.argument("learning_id")
@click.option("--reason", required=True, help="Why it is refused. Kept on the row.")
@click.option("--actor", default="", help="Who rejected it.")
def learn_reject(learning_id: str, reason: str, actor: str) -> None:
    """Refuse a lesson, keeping the reason."""
    from .config import load_config
    from .learning import LearningError, promotion

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            decision = promotion.reject(
                session, learning_id=learning_id, reason=reason, actor=actor
            )
            _emit(decision.to_wire(), None)
    except LearningError as err:
        raise click.ClickException(str(err)) from err


@learn.command("rollback")
@click.argument("learning_id")
@click.option("--reason", required=True, help="Why it is being taken out of force. Kept on the row.")
@click.option("--actor", default="", help="Who rolled it back.")
def learn_rollback(learning_id: str, reason: str, actor: str) -> None:
    """Take a promoted lesson out of force."""
    from .config import load_config
    from .learning import LearningError, promotion

    config = load_config()
    init_engine(config.database_url)
    try:
        with session_scope() as session:
            decision = promotion.rollback(
                session, learning_id=learning_id, reason=reason, actor=actor
            )
            _emit(decision.to_wire(), None)
            if not decision.ok:
                raise click.ClickException(decision.reason)
    except LearningError as err:
        raise click.ClickException(str(err)) from err


@learn.command("active")
@click.option("--kind", default="", help="Filter to one lesson kind.")
@click.option("--tenant", "tenant_id", default="", help="Filter to one tenant.")
def learn_active(kind: str, tenant_id: str) -> None:
    """Print the lessons currently in force."""
    from .config import load_config
    from .learning import registry

    config = load_config()
    init_engine(config.database_url)
    with session_scope() as session:
        rows = registry.active_lessons(session, tenant_id=tenant_id, kind=kind)
        _emit({"active": [row.to_wire() for row in rows], "count": len(rows)}, None)
