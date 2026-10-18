"""Chain proposals and the structural review every proposal must pass.

A chain is a claim that several *already reproduced* findings can be wired
together so that one step's output is the next step's input. The model writes
the wiring; this module is what decides whether the wiring is even a chain
before anything runs:

* the first step must start from the unauthenticated position and each step's
  end state must be the next step's start state, so the states form one path;
* every referenced finding must exist and must already have been reproduced on
  its own — a chain never introduces a finding nobody proved;
* every ``{{VALUE}}`` a step needs must be produced by an earlier step's
  extraction map, so the data flow is real and not a placeholder nobody fills;
* every extraction selector must be one this build can execute, with the fields
  that source needs present.

None of it decides that the chain worked. That is the sandbox's job, and only
the sandbox's verdict admits edges into the attack graph.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .graph import ACQUISITIONS

# Matches the depth `AttackGraph.all_chains` searches: a longer proposal would
# describe a path the graph could never hold.
MAX_STEPS = 6

PLACEHOLDER = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
EXTRACT_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
REQUEST_LINE = re.compile(r"^[A-Z]{3,8} \S+ HTTP/1\.[01]$")

# The extraction sources the sandbox harness implements. Kept as a frozenset so
# an unknown source is refused here rather than failing mid-chain in a container.
EXTRACT_SOURCES = frozenset({"status", "body", "header", "json", "json_text", "base64", "base64url", "jwt_hs256"})
PICK_MODES = frozenset({"first", "last", "longest", "first_starts_with", "first_contains", "first_matching"})
PICK_REQUIRES = {
    "first_starts_with": "starts_with",
    "first_contains": "contains",
    "first_matching": "pattern",
}
REQUIRED_FIELDS = {
    "header": ("name",),
    "json": ("path",),
    "json_text": ("path",),
    "base64": ("value",),
    "base64url": ("value",),
    "jwt_hs256": ("secret",),
}


class ChainPlanError(ValueError):
    """A proposal was reviewed and refused. Carries every problem, not the first."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = list(problems)
        super().__init__("chain proposal refused:\n  - " + "\n  - ".join(self.problems))


@dataclass(frozen=True)
class StepPlan:
    """One hop of a chain: what it needs, what it does, what it produces."""

    finding_id: str
    state_before: str
    state_after: str
    description: str
    expect_expr: str | None
    extract: dict[str, dict[str, Any]]
    setup: dict[str, Any] | None
    followup: dict[str, Any] | None


@dataclass(frozen=True)
class ChainPlan:
    """A reviewed chain: the steps form one connected path over real findings."""

    title: str
    rationale: str
    steps: tuple[StepPlan, ...]

    @property
    def finding_ids(self) -> tuple[str, ...]:
        return tuple(step.finding_id for step in self.steps)

    @property
    def states(self) -> tuple[str, ...]:
        """The state path: the first step's entry state, then every step's exit."""
        return (self.steps[0].state_before,) + tuple(step.state_after for step in self.steps)


def _state_problem(raw: Any, where: str) -> str | None:
    if not isinstance(raw, str) or ":" not in raw:
        return f"{where} must be a state like `kind:resource`, got {raw!r}"
    kind, _, resource = raw.partition(":")
    if kind not in ACQUISITIONS:
        return f"{where} names unknown acquisition {kind!r}; expected one of {sorted(ACQUISITIONS)}"
    if not resource:
        return f"{where} names no resource (`kind:resource`)"
    return None


def _selector_problems(name: str, selector: Any, where: str) -> list[str]:
    problems: list[str] = []
    if not EXTRACT_NAME.match(name):
        problems.append(f"{where}: extraction name {name!r} must be upper-case A-Z0-9_")
    if not isinstance(selector, dict):
        return problems + [f"{where}: extraction {name} must be an object"]
    source = selector.get("from")
    if source not in EXTRACT_SOURCES:
        problems.append(f"{where}: extraction {name} has unknown source {source!r}; expected one of {sorted(EXTRACT_SOURCES)}")
        return problems
    for field in REQUIRED_FIELDS.get(str(source), ()):
        if not selector.get(field):
            problems.append(f"{where}: extraction {name} from {source!r} needs `{field}`")
    pick = selector.get("pick")
    if pick is not None:
        if pick not in PICK_MODES:
            problems.append(f"{where}: extraction {name} has unknown pick {pick!r}; expected one of {sorted(PICK_MODES)}")
        elif pick in PICK_REQUIRES and not selector.get(PICK_REQUIRES[pick]):
            problems.append(f"{where}: extraction {name} with pick {pick!r} needs `{PICK_REQUIRES[pick]}`")
    if source == "jwt_hs256" and not isinstance(selector.get("claims"), dict):
        problems.append(f"{where}: extraction {name} from jwt_hs256 needs `claims` as an object")
    return problems


def _selector_strings(selector: Any) -> list[str]:
    """Every string a selector contains. `fillSelector` substitutes all of them."""
    if isinstance(selector, str):
        return [selector]
    if isinstance(selector, list):
        return [text for item in selector for text in _selector_strings(item)]
    if isinstance(selector, dict):
        return [text for value in selector.values() for text in _selector_strings(value)]
    return []


def _needed(raw: str) -> list[str]:
    return [match.group(1) for match in PLACEHOLDER.finditer(str(raw))]


def _request_problems(raw: Any, where: str) -> list[str]:
    if not isinstance(raw, str) or not raw.strip():
        return [f"{where}: finding has no PoC `request` to replay"]
    first = raw.replace("\r\n", "\n").split("\n", 1)[0].strip()
    if not REQUEST_LINE.match(first):
        return [f"{where}: PoC request does not start with a raw HTTP request line (got {first[:60]!r})"]
    return []


def review_plan(raw: Mapping[str, Any], findings: Mapping[str, Mapping[str, Any]]) -> tuple[ChainPlan | None, list[str]]:
    """Parse and review a proposal. Returns (plan, problems); problems empty means usable."""
    problems: list[str] = []
    if not isinstance(raw, Mapping):
        return None, ["proposal is not an object"]

    title = str(raw.get("title") or "").strip()
    if not title:
        problems.append("proposal has no `title`")
    rationale = str(raw.get("rationale") or "")

    raw_steps = raw.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        return None, problems + ["proposal has no `steps` list"]
    if len(raw_steps) < 2:
        return None, problems + [f"a chain needs at least two steps, got {len(raw_steps)}"]
    if len(raw_steps) > MAX_STEPS:
        return None, problems + [f"a chain may hold at most {MAX_STEPS} steps, got {len(raw_steps)}"]

    steps: list[StepPlan] = []
    produced: set[str] = set()  # values an earlier step must have extracted
    seen_findings: set[str] = set()

    for index, item in enumerate(raw_steps):
        where = f"step {index + 1}"
        if not isinstance(item, Mapping):
            problems.append(f"{where} is not an object")
            continue
        finding_id = str(item.get("finding_id") or "")
        finding = findings.get(finding_id)
        if not finding_id:
            problems.append(f"{where} names no finding")
        elif finding is None:
            problems.append(f"{where} references {finding_id!r}, which is not a finding from this scan")
        elif not finding.get("reproduced"):
            problems.append(f"{where} references {finding_id!r}, which never reproduced on its own")
        elif finding_id in seen_findings:
            problems.append(f"{where} repeats {finding_id!r}; a chain steps forward, it does not loop")
        seen_findings.add(finding_id)

        state_before = str(item.get("state_before") or "")
        state_after = str(item.get("state_after") or "")
        for value, label in ((state_before, "state_before"), (state_after, "state_after")):
            problem = _state_problem(value, f"{where} {label}")
            if problem:
                problems.append(problem)

        poc = (finding or {}).get("poc") if isinstance((finding or {}).get("poc"), dict) else {}
        request = poc.get("request", "")
        problems.extend(_request_problems(request, where))

        expect_expr = item.get("expect_expr") or poc.get("expect_expr")
        if not expect_expr:
            problems.append(f"{where} has neither its own `expect_expr` nor one on the finding's PoC")

        # Requests may only use values an earlier step produced; a value a later
        # step produces is not available yet and would be sent literally.
        for name in _needed(request):
            if name not in produced:
                problems.append(
                    f"{where} request needs {{{{{name}}}}} but no earlier step extracts it"
                )

        extract = item.get("extract") or {}
        if not isinstance(extract, Mapping):
            problems.append(f"{where} `extract` must be an object")
            extract = {}
        scope = set(produced)
        for name, selector in extract.items():
            problems.extend(_selector_problems(str(name), selector, where))
            # A selector may use values from earlier steps, or from earlier
            # entries of the same map (the harness walks the map in order).
            for text in _selector_strings(selector):
                for referenced in _needed(text):
                    if referenced not in scope:
                        problems.append(
                            f"{where} extraction {name} needs {{{{{referenced}}}}} but nothing produced it yet"
                        )
            scope.add(str(name))
        produced |= set(str(name) for name in extract)

        setup = item.get("setup")
        followup = item.get("followup")
        for label, spec in (("setup", setup), ("followup", followup)):
            if spec is None:
                continue
            if not isinstance(spec, Mapping) or not spec.get("request"):
                problems.append(f"{where} {label} must be an object with a `request`")
                continue
            for name in _needed(spec["request"]):
                if name not in produced:
                    problems.append(f"{where} {label} needs {{{{{name}}}}} but no earlier step extracts it")

        steps.append(
            StepPlan(
                finding_id=finding_id,
                state_before=state_before,
                state_after=state_after,
                description=str(item.get("description") or (finding or {}).get("title") or ""),
                expect_expr=str(expect_expr) if expect_expr else None,
                extract={str(k): dict(v) for k, v in extract.items() if isinstance(v, Mapping)},
                setup=dict(setup) if isinstance(setup, Mapping) else None,
                followup=dict(followup) if isinstance(followup, Mapping) else None,
            )
        )

    # The states have to form one path: start unauthenticated, and each step's
    # exit is the next step's entry. Anything else is not a chain.
    if steps:
        if steps[0].state_before.split(":", 1)[0] != "none":
            problems.append(
                f"the chain starts at {steps[0].state_before!r}; a chain must start from `none:*`, "
                "because every step before it would have to be in the chain too"
            )
        for index in range(len(steps) - 1):
            if steps[index].state_after != steps[index + 1].state_before:
                problems.append(
                    f"step {index + 1} ends at {steps[index].state_after!r} but step {index + 2} "
                    f"starts at {steps[index + 1].state_before!r}; the states do not connect"
                )

    if problems:
        return None, problems
    return ChainPlan(title=title, rationale=rationale, steps=tuple(steps)), []
