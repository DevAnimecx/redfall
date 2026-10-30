"""The learning loop: verified outcomes become tested, reversible practice.

One doctrine governs this package, and it is the same one the evidence ledger
enforces: **nothing is learned that was not first reproduced.** A lesson cites
an E3/E4 evidence record — not a model's opinion, not a hypothesis, not a
plausible-sounding suggestion — and a lesson that cannot cite one is refused at
creation rather than filtered later.

What the loop does with a lesson is deliberately slow:

1. ``propose`` stores it as a candidate, tied to the record that produced it.
2. ``shadow`` runs it beside current behaviour and records how often the two
   disagree, without applying it.
3. ``evaluate`` compares it to the incumbent on a holdout.
4. ``promote`` puts it in force, and only if the gate passes — and the gate is
   re-checked at promotion rather than trusted from an earlier call.
5. ``rollback`` takes it out again, keeping the reason and the version it
   replaced.

A loop that skipped to step 4 would be a system that believes its own output.
The point of the other four steps is that it does not.
"""

from .promotion import (
    GateDecision,
    evaluate,
    gate_constants,
    promote,
    reject,
    rollback,
    rollback_plan,
    shadow,
)
from .registry import (
    CONFIDENCE_SATURATION,
    LEARNABLE_GRADES,
    LESSON_KINDS,
    LearningError,
    confidence_for,
    active_lessons,
    history,
    list_learnings,
    propose,
)

__all__ = [
    "CONFIDENCE_SATURATION",
    "GateDecision",
    "LEARNABLE_GRADES",
    "LESSON_KINDS",
    "LearningError",
    "active_lessons",
    "confidence_for",
    "evaluate",
    "gate_constants",
    "history",
    "list_learnings",
    "promote",
    "propose",
    "reject",
    "rollback",
    "rollback_plan",
    "shadow",
]
