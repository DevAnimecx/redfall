"""Policy-as-code: operator rules evaluated before an action runs.

A rule is a small, checkable statement — *effect*, *action pattern*,
*condition* — stored per tenant. The engine evaluates the rules that match a
call and returns a decision with the rule that produced it, so a refusal always
names the reason and an operator can see which line of their policy bit.

Three decisions shape the implementation:

**A tenant with no rules is closed; a call no rule addresses is open.** The two
readings are opposite and both are deliberate.

*No rules at all* means the operator turned policy on without writing any, so
the engine denies (`defaulted=True`) and says so — an empty policy that allowed
everything would make the feature a no-op that looks like enforcement.
``REDFALL_POLICY=open`` flips this for a deployment that wants rules to be
additive.

*A call no rule addresses* is different: the policy is silent about it, and
silence is not a prohibition. This is what makes a condition usable. A rule
that denies scans of ``/srv/classified`` must leave scans of ``/srv/public``
alone — if "no match" denied, narrowing a rule would silently deny everything
it was not written about, and operators would learn not to write conditions at
all. The one case that is genuinely closed by silence is a rule whose *pattern*
covers the action and whose condition did not hold, and that is not silence:
`explain()` shows the rule and the clause that failed.

**Priority decides, and deny wins ties.** An explicit prohibition at the same
priority as a broad permission must not be lost to rule ordering.

**Conditions are data, not code.** A condition is a small mapping of field,
operator and value — ``{"arg.target": {"prefix": "/srv"}}``. There is no
expression language and no ``eval``, so a policy file cannot execute anything.
The no-mock contract forbids `eval` in `src/` for the same reason, and a policy
engine is exactly where the temptation to add one lives.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..store.models_tenant import PolicyRule

ENV_POLICY = "REDFALL_POLICY"

EFFECT_ALLOW = "allow"
EFFECT_DENY = "deny"
EFFECTS = (EFFECT_ALLOW, EFFECT_DENY)

# Condition operators. Each is a pure function of (value, expected) returning a
# bool, so a rule can be tested without a running engine.
OPERATORS = (
    "equals",
    "not_equals",
    "prefix",
    "suffix",
    "contains",
    "in",
    "not_in",
    "exists",
    "matches",
    "gt",
    "lt",
)


class PolicyError(RuntimeError):
    """A rule is malformed, or the policy file could not be read."""

    code = "policy_error"


@dataclass(frozen=True)
class Decision:
    """The outcome of evaluating a call against a tenant's rules."""

    allowed: bool
    action: str
    tenant_id: str
    reason: str
    rule_id: str = ""
    rule_name: str = ""
    defaulted: bool = False

    def to_wire(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "tenant_id": self.tenant_id,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "defaulted": self.defaulted,
        }


@dataclass(frozen=True)
class Rule:
    """A policy rule, detached from its row so it can be evaluated anywhere."""

    id: str
    name: str
    effect: str
    action: str
    condition: dict[str, Any]
    priority: int
    enabled: bool = True

    def matches_action(self, action: str) -> bool:
        return fnmatch.fnmatchcase(action, self.action)

    def matches_condition(self, context: dict[str, Any]) -> tuple[bool, str]:
        """Whether every clause holds, with the first clause that failed."""
        for field, spec in (self.condition or {}).items():
            ok, why = _check_clause(field, spec, context)
            if not ok:
                return False, why
        return True, ""


def _dig(context: dict[str, Any], path: str) -> Any:
    """Read a dotted path out of the call context. Missing yields a sentinel."""
    current: Any = context
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


class _Missing:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return "<missing>"


_MISSING = _Missing()


def validate_condition(condition: dict[str, Any]) -> None:
    """Reject a malformed condition without needing a call to test it against.

    Checking an operator by *evaluating* the rule does not work: a rule whose
    field is absent from the empty context short-circuits before the operator is
    ever consulted, so an unknown operator stored under a field nobody supplies
    would pass validation and only surface on the day some caller happened to
    pass that field. This walks the structure and checks the operators directly.
    """
    for field, spec in (condition or {}).items():
        if not isinstance(field, str) or not field.strip():
            raise PolicyError(f"condition field names must be non-empty strings, got {field!r}")
        clauses = spec if isinstance(spec, dict) else {"equals": spec}
        for op, expected in clauses.items():
            if op not in OPERATORS:
                raise PolicyError(
                    f"unknown operator {op!r} for field {field!r}; "
                    f"known: {', '.join(OPERATORS)}"
                )
            if op == "matches":
                try:
                    re.compile(str(expected))
                except re.error as exc:
                    raise PolicyError(
                        f"field {field!r}: invalid pattern {expected!r}: {exc}"
                    ) from exc
            if op in ("in", "not_in") and not isinstance(expected, (list, tuple, set)):
                raise PolicyError(f"field {field!r}: {op} needs a list, got {type(expected).__name__}")


def _check_clause(field: str, spec: Any, context: dict[str, Any]) -> tuple[bool, str]:
    """Evaluate one condition clause.

    A bare value is shorthand for ``equals``. An explicit operator is a
    one-key mapping, which keeps the policy file readable without a grammar.
    """
    value = _dig(context, field)
    if not isinstance(spec, dict):
        spec = {"equals": spec}

    for op, expected in spec.items():
        if op not in OPERATORS:
            raise PolicyError(
                f"unknown operator {op!r} for field {field!r}; known: {', '.join(OPERATORS)}"
            )
        ok = _apply(op, value, expected, field)
        if not ok:
            return False, f"{field} {op} {expected!r} did not hold"
    return True, ""


def _apply(op: str, value: Any, expected: Any, field: str) -> bool:
    missing = value is _MISSING
    if op == "exists":
        return (not missing) == bool(expected)
    if missing:
        # Every other operator needs a value. A missing field never matches,
        # which keeps a rule from firing on an argument that was not supplied.
        return False
    if op == "equals":
        return value == expected
    if op == "not_equals":
        return value != expected
    if op == "prefix":
        return isinstance(value, str) and str(value).startswith(str(expected))
    if op == "suffix":
        return isinstance(value, str) and str(value).endswith(str(expected))
    if op == "contains":
        if isinstance(value, str):
            return str(expected) in value
        if isinstance(value, (list, tuple, set)):
            return expected in value
        return False
    if op == "in":
        return isinstance(expected, (list, tuple, set)) and value in expected
    if op == "not_in":
        return isinstance(expected, (list, tuple, set)) and value not in expected
    if op == "matches":
        # Anchored at both ends: an unanchored pattern in a policy rule is far
        # more likely a mistake that widens the rule than an intent.
        try:
            return re.fullmatch(str(expected), str(value)) is not None
        except re.error as exc:
            raise PolicyError(f"field {field!r}: invalid pattern {expected!r}: {exc}") from exc
    if op == "gt":
        return _numeric(value) is not None and _numeric(value) > _numeric(expected)
    if op == "lt":
        return _numeric(value) is not None and _numeric(value) < _numeric(expected)
    raise PolicyError(f"unhandled operator {op!r}")


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_rule(
    session: Session,
    *,
    tenant_id: str,
    effect: str,
    action: str,
    name: str = "",
    condition: dict[str, Any] | None = None,
    priority: int = 0,
) -> PolicyRule:
    """Store a rule after validating its shape. An invalid rule never lands."""
    clean_effect = (effect or "").strip().lower()
    if clean_effect not in EFFECTS:
        raise PolicyError(f"effect must be one of {', '.join(EFFECTS)}")
    clean_action = (action or "").strip()
    if not clean_action:
        raise PolicyError("action pattern must be a non-empty string")
    cond = dict(condition or {})
    # Validate the structure at write time rather than trusting a later
    # evaluation to surface a typo: a rule with an unknown operator must never
    # reach the database, where it would look configured but match nothing.
    validate_condition(cond)
    row = PolicyRule(
        id=f"pol-{secrets.token_hex(12)}",
        tenant_id=tenant_id,
        name=name or clean_action,
        effect=clean_effect,
        action=clean_action,
        condition=cond,
        priority=priority,
    )
    session.add(row)
    session.flush()
    return row


def list_rules(session: Session, *, tenant_id: str, enabled_only: bool = False) -> list[PolicyRule]:
    stmt = (
        select(PolicyRule)
        .where(PolicyRule.tenant_id == tenant_id)
        .order_by(PolicyRule.priority.desc(), PolicyRule.created_at.asc())
    )
    if enabled_only:
        stmt = stmt.where(PolicyRule.enabled.is_(True))
    return list(session.scalars(stmt).all())


def delete_rule(session: Session, *, tenant_id: str, rule_id: str) -> bool:
    row = session.get(PolicyRule, rule_id)
    if row is None or row.tenant_id != tenant_id:
        return False
    session.delete(row)
    session.flush()
    return True


def load_rule_file(path: str, *, tenant_id: str = "") -> list[dict[str, Any]]:
    """Read a policy file: a JSON document with a ``rules`` list.

    Validated here, before anything is written, so a bad file leaves the stored
    policy untouched instead of half-applied.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy file {path} is not valid JSON: {exc}") from exc

    if isinstance(document, list):
        raw_rules = document
    elif isinstance(document, dict):
        if tenant_id and document.get("tenant_id") and document["tenant_id"] != tenant_id:
            raise PolicyError(
                f"policy file names tenant {document['tenant_id']!r}, not {tenant_id!r}"
            )
        raw_rules = document.get("rules") or []
    else:
        raise PolicyError("policy file must be a JSON object with a 'rules' list")
    if not isinstance(raw_rules, list):
        raise PolicyError("'rules' must be a list")

    checked: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise PolicyError(f"rule {index} is not an object")
        entry = {
            "effect": raw.get("effect", ""),
            "action": raw.get("action", ""),
            "name": raw.get("name", ""),
            "condition": raw.get("condition") or {},
            "priority": int(raw.get("priority") or 0),
        }
        try:
            if str(entry["effect"]).strip().lower() not in EFFECTS:
                raise PolicyError(f"effect must be one of {', '.join(EFFECTS)}")
            if not entry["action"]:
                raise PolicyError("action pattern must be a non-empty string")
            validate_condition(dict(entry["condition"]))
        except PolicyError as exc:
            raise PolicyError(f"rule {index} ({entry['name'] or entry['action']}): {exc}") from exc
        checked.append(entry)
    return checked


class PolicyEngine:
    """Evaluates a tenant's rules. Constructed per call site, not global."""

    def __init__(self, session: Session, *, tenant_id: str) -> None:
        self.session = session
        self.tenant_id = tenant_id

    def rules(self) -> list[Rule]:
        return [
            Rule(
                id=row.id,
                name=row.name,
                effect=row.effect,
                action=row.action,
                condition=row.condition or {},
                priority=row.priority,
                enabled=row.enabled,
            )
            for row in list_rules(self.session, tenant_id=self.tenant_id, enabled_only=True)
        ]

    def decide(self, action: str, context: dict[str, Any] | None = None) -> Decision:
        """The decision for one action, naming the rule that produced it."""
        rules = self.rules()
        if not rules:
            return Decision(
                allowed=self.default_allow(),
                action=action,
                tenant_id=self.tenant_id,
                reason=(
                    "no policy rules configured"
                    if self.default_allow()
                    else "no policy rules configured; policy defaults to deny"
                ),
                defaulted=True,
            )

        matched: list[tuple[Rule, str]] = []
        for rule in rules:
            if not rule.matches_action(action):
                continue
            ok, why = rule.matches_condition(context or {})
            if ok:
                matched.append((rule, ""))

        if not matched:
            # Rules exist, but none applies to this call. That can only mean
            # the policy is silent about it: a rule whose pattern covers the
            # action but whose *condition* did not hold does not apply, which
            # is exactly what writing a condition means. Treating that as a
            # denial would make every conditional rule a trap — an operator
            # narrowing "deny scans of /srv/classified" would find they had
            # also denied scans of everything else.
            return Decision(
                allowed=True,
                action=action,
                tenant_id=self.tenant_id,
                reason=f"no rule applies to {action!r}",
                defaulted=True,
            )

        # Highest priority first; at equal priority a deny outranks an allow.
        matched.sort(key=lambda item: (item[0].priority, item[0].effect == EFFECT_DENY), reverse=True)
        chosen, _ = matched[0]
        allowed = chosen.effect == EFFECT_ALLOW
        return Decision(
            allowed=allowed,
            action=action,
            tenant_id=self.tenant_id,
            reason=(
                f"allowed by rule {chosen.name!r}"
                if allowed
                else f"denied by rule {chosen.name!r}"
            ),
            rule_id=chosen.id,
            rule_name=chosen.name,
        )

    def default_allow(self) -> bool:
        """Whether an unmatched action is allowed.

        Policy is closed by default when enforced: an operator who wrote rules
        asked for those rules to matter. ``REDFALL_POLICY=open`` flips this for
        a deployment that wants allow-listing to be additive.
        """
        return os.getenv(ENV_POLICY, "").strip().lower() in {"open", "permissive", "allow"}

    def explain(self, action: str, context: dict[str, Any] | None = None) -> dict[str, object]:
        """Every rule that applies, why each did or did not match, and the verdict.

        This is the answer to "why was I blocked": a rule list an operator can
        act on, not a single boolean.
        """
        context = context or {}
        evaluations: list[dict[str, object]] = []
        for rule in self.rules():
            action_match = rule.matches_action(action)
            condition_match, why = rule.matches_condition(context) if action_match else (False, "action pattern did not match")
            evaluations.append(
                {
                    "rule_id": rule.id,
                    "name": rule.name,
                    "effect": rule.effect,
                    "priority": rule.priority,
                    "action_matched": action_match,
                    "condition_matched": condition_match,
                    "reason": why,
                }
            )
        decision = self.decide(action, context)
        return {"decision": decision.to_wire(), "rules": evaluations}
