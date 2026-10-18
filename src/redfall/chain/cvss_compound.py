"""Combined severity for a multi-step chain.

A chain's score is not the maximum of its hops and not their sum. Two 9.8s that
each need the other to matter are not a 19.6, and a chain whose second step
requires an already-compromised machine is not a second full compromise either.

The model is deliberately small enough to reason about without a reference
implementation:

* The first hop contributes its full CVSS — that is what an attacker achieves
  with no prior position.
* Every later hop contributes a discounted share, because it is reachable only
  through the hop before it. The discount compounds, so deep chains saturate
  instead of growing without bound.
* A chain cannot score below its worst single step. A two-step path to the same
  impact is strictly harder to pull off than the one step alone, and a score that
  implied otherwise would be telling the reader the chain made things safer.
* A hop that crosses a trust boundary (guest to host, low privilege to admin) is
  applied as a scope modifier. It lifts the result above the base, and the 10.0
  cap is what keeps the lift honest.
"""

from __future__ import annotations

from typing import Iterable

# Fraction of a follow-on hop that still counts as new impact.
LATER_HOP_WEIGHT = 0.5

# How much a single trust-boundary crossing lifts the base, as a fraction.
BOUNDARY_LIFT = 0.08

# Diminishing return on successive boundary crossings.
BOUNDARY_DECAY = 0.6

MAX_SCORE = 10.0


def compound_cvss(hop_scores: Iterable[float], boundary_scores: Iterable[float] = ()) -> float:
    """Combine hop severities into one score in [0, 10].

    `hop_scores` is ordered, first hop first. `boundary_scores` holds the severity
    of the hops that crossed a trust boundary; their magnitude decides how much
    the crossing lifts the result.
    """
    hops = [max(0.0, min(MAX_SCORE, float(s))) for s in hop_scores]
    if not hops:
        return 0.0

    weighted = hops[0]
    weight = LATER_HOP_WEIGHT
    for score in hops[1:]:
        weighted += score * weight
        weight *= LATER_HOP_WEIGHT

    lifts = sorted((max(0.0, min(MAX_SCORE, float(s))) for s in boundary_scores), reverse=True)
    factor = 1.0
    decay = 1.0
    for score in lifts:
        factor += BOUNDARY_LIFT * decay * (score / MAX_SCORE)
        decay *= BOUNDARY_DECAY

    # Floor at the worst hop: chaining can only add risk, never remove it.
    return round(min(MAX_SCORE, max(max(hops), weighted * factor)), 2)


def chain_severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# The band floors of the CVSS v3 rating scale. The analysis stage assigns a
# band, not a vector, so a finding is placed at the lowest score its band can
# mean. That is the conservative reading: nothing here claims a severity the
# analysis did not state, and a chain can only be as strong as the bands under it.
SEVERITY_FLOOR: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
}


def severity_score(severity: str | None) -> float | None:
    """The CVSS floor of a severity band, or None when the band is unknown."""
    return SEVERITY_FLOOR.get(str(severity or "").strip().lower())


def uplift_over_worst_hop(hop_scores: Iterable[float], compound: float) -> float:
    """How much more dangerous the chain is than its single worst step.

    This is the number that justifies chaining existing at all: if it is zero or
    negative, the chain told the reader nothing a single finding would not have.
    """
    hops = list(hop_scores)
    if not hops:
        return 0.0
    return round(compound - max(hops), 2)
