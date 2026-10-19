"""The campaign state machine.

The transitions are deliberately explicit. A campaign cannot jump from
``draft`` to ``reported`` or resume from ``paused`` into an arbitrary phase; the
caller must name the phase it is returning to. This keeps the audit trail
readable after an interruption and prevents an agent from skipping the
verification phases.
"""

from __future__ import annotations

from enum import Enum


class CampaignState(str, Enum):
    DRAFT = "draft"
    SCOPED = "scoped"
    INDEXING = "indexing"
    RECON = "recon"
    HYPOTHESIS = "hypothesis"
    PROBE = "probe"
    EXPLOIT = "exploit"
    IMPACT = "impact"
    FIX = "fix"
    VERIFY = "verify"
    REPORTED = "reported"
    PAUSED = "paused"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"


ACTIVE_STATES = frozenset(
    {
        CampaignState.INDEXING,
        CampaignState.RECON,
        CampaignState.HYPOTHESIS,
        CampaignState.PROBE,
        CampaignState.EXPLOIT,
        CampaignState.IMPACT,
        CampaignState.FIX,
        CampaignState.VERIFY,
    }
)

SIDE_STATES = frozenset(
    {
        CampaignState.PAUSED,
        CampaignState.BLOCKED,
    }
)

TERMINAL_STATES = frozenset(
    {
        CampaignState.REPORTED,
        CampaignState.FAILED,
        CampaignState.CANCELLED,
    }
)

# The happy path plus the two legitimate backward moves: a failed probe can
# return to hypothesis, and a failed verification can return to repair.
ALLOWED: dict[CampaignState, frozenset[CampaignState]] = {
    CampaignState.DRAFT: frozenset({CampaignState.SCOPED, CampaignState.CANCELLED}),
    CampaignState.SCOPED: frozenset(
        {CampaignState.INDEXING, CampaignState.PAUSED, CampaignState.BLOCKED, CampaignState.CANCELLED, CampaignState.FAILED}
    ),
    CampaignState.INDEXING: frozenset(
        {CampaignState.RECON, CampaignState.PAUSED, CampaignState.BLOCKED, CampaignState.CANCELLED, CampaignState.FAILED}
    ),
    CampaignState.RECON: frozenset(
        {
            CampaignState.HYPOTHESIS,
            CampaignState.REPORTED,
            CampaignState.PAUSED,
            CampaignState.BLOCKED,
            CampaignState.CANCELLED,
            CampaignState.FAILED,
        }
    ),
    CampaignState.HYPOTHESIS: frozenset(
        {
            CampaignState.PROBE,
            CampaignState.REPORTED,
            CampaignState.PAUSED,
            CampaignState.BLOCKED,
            CampaignState.CANCELLED,
            CampaignState.FAILED,
        }
    ),
    CampaignState.PROBE: frozenset(
        {
            CampaignState.EXPLOIT,
            CampaignState.HYPOTHESIS,
            CampaignState.REPORTED,
            CampaignState.PAUSED,
            CampaignState.BLOCKED,
            CampaignState.CANCELLED,
            CampaignState.FAILED,
        }
    ),
    CampaignState.EXPLOIT: frozenset(
        {
            CampaignState.IMPACT,
            CampaignState.HYPOTHESIS,
            CampaignState.REPORTED,
            CampaignState.PAUSED,
            CampaignState.BLOCKED,
            CampaignState.CANCELLED,
            CampaignState.FAILED,
        }
    ),
    CampaignState.IMPACT: frozenset(
        {
            CampaignState.FIX,
            CampaignState.REPORTED,
            CampaignState.PAUSED,
            CampaignState.BLOCKED,
            CampaignState.CANCELLED,
            CampaignState.FAILED,
        }
    ),
    CampaignState.FIX: frozenset(
        {
            CampaignState.VERIFY,
            CampaignState.REPORTED,
            CampaignState.PAUSED,
            CampaignState.BLOCKED,
            CampaignState.CANCELLED,
            CampaignState.FAILED,
        }
    ),
    CampaignState.VERIFY: frozenset(
        {
            CampaignState.REPORTED,
            CampaignState.FIX,
            CampaignState.PAUSED,
            CampaignState.BLOCKED,
            CampaignState.CANCELLED,
            CampaignState.FAILED,
        }
    ),
    CampaignState.REPORTED: frozenset(),
    CampaignState.FAILED: frozenset(),
    CampaignState.CANCELLED: frozenset(),
    # Paused and blocked can only return to a named previous state, cancel or
    # fail. The service enforces the "previous" half.
    CampaignState.PAUSED: frozenset(
        {CampaignState.SCOPED, CampaignState.INDEXING, CampaignState.RECON, CampaignState.HYPOTHESIS,
         CampaignState.PROBE, CampaignState.EXPLOIT, CampaignState.IMPACT, CampaignState.FIX,
         CampaignState.VERIFY, CampaignState.CANCELLED, CampaignState.FAILED}
    ),
    CampaignState.BLOCKED: frozenset(
        {CampaignState.SCOPED, CampaignState.INDEXING, CampaignState.RECON, CampaignState.HYPOTHESIS,
         CampaignState.PROBE, CampaignState.EXPLOIT, CampaignState.IMPACT, CampaignState.FIX,
         CampaignState.VERIFY, CampaignState.CANCELLED, CampaignState.FAILED}
    ),
}

# Used by the CLI/agent when it wants the next happy-path state. A probe may
# still choose to go back to hypothesis; this map is not the only transition.
NEXT: dict[CampaignState, CampaignState] = {
    CampaignState.SCOPED: CampaignState.INDEXING,
    CampaignState.INDEXING: CampaignState.RECON,
    CampaignState.RECON: CampaignState.HYPOTHESIS,
    CampaignState.HYPOTHESIS: CampaignState.PROBE,
    CampaignState.PROBE: CampaignState.EXPLOIT,
    CampaignState.EXPLOIT: CampaignState.IMPACT,
    CampaignState.IMPACT: CampaignState.REPORTED,
    CampaignState.FIX: CampaignState.VERIFY,
    CampaignState.VERIFY: CampaignState.REPORTED,
}


def parse_state(value: str | CampaignState) -> CampaignState:
    if isinstance(value, CampaignState):
        return value
    try:
        return CampaignState(str(value).strip().lower())
    except ValueError as exc:
        valid = ", ".join(state.value for state in CampaignState)
        raise ValueError(f"unknown campaign state {value!r}; valid states: {valid}") from exc


def ensure_transition(
    current: CampaignState,
    target: CampaignState,
    *,
    previous: CampaignState | None = None,
) -> None:
    """Raise ValueError when ``current -> target`` is not legal.

    ``previous`` is required when leaving paused/blocked: it must equal the
    target, so a resumed campaign cannot silently jump elsewhere.
    """
    if current in TERMINAL_STATES:
        raise ValueError(f"campaign is terminal ({current.value}) and cannot transition to {target.value}")
    if target not in ALLOWED[current]:
        allowed = ", ".join(sorted(state.value for state in ALLOWED[current])) or "none"
        raise ValueError(f"invalid campaign transition {current.value} -> {target.value}; allowed: {allowed}")
    if current in SIDE_STATES and target not in {CampaignState.CANCELLED, CampaignState.FAILED}:
        if previous is None:
            raise ValueError(f"resuming from {current.value} requires the previous state")
        if target != previous:
            raise ValueError(
                f"resume target {target.value} does not match previous state {previous.value}"
            )


def is_active(value: str | CampaignState) -> bool:
    return parse_state(value) in ACTIVE_STATES


def is_terminal(value: str | CampaignState) -> bool:
    return parse_state(value) in TERMINAL_STATES
