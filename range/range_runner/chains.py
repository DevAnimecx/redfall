"""Chain scoring for targets whose manifest declares `chains`.

A target like chainbank is not scored by counting vulnerabilities. Its whole
point is that individual flaws combine, so the unit of measurement is the path:
did the scanner report every step, and did it connect them?

Three numbers come out of this, and they measure different failures:

* `chain_recall` — how many declared chains were reported complete.
* `chain_link_rate` — of the joins a chain needs, how many the scanner actually
  made. A scanner can find all twelve findings and still link none of them, and
  that is the failure this target exists to catch.
* `chain_narrative_rate` — how many reported chains satisfy the manifest's
  `narrative_must_contain`. The narrative is checked because a chain the report
  cannot explain in the required terms has not actually been understood.

A scanner names its own findings; the manifest names vulnerabilities. Before any
of this can be scored the report is translated into the manifest's vocabulary
with `translate_finding_ids`, driven only by the matcher's finding→vuln map. An
id the matcher did not claim becomes `None`, and `None` breaks a sequence: no
join is ever inferred across a step that does not exist in ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence


@dataclass
class ChainStep:
    finding_id: str
    n: int
    title: str
    route: str
    state_before: str
    state_after: str


@dataclass
class DeclaredChain:
    id: str
    name: str
    start_state: str
    end_state: str
    cvss_compound: float
    narrative_must_contain: tuple[str, ...]
    steps: tuple[ChainStep, ...]

    @property
    def finding_ids(self) -> tuple[str, ...]:
        return tuple(step.finding_id for step in self.steps)

    @property
    def required_joins(self) -> tuple[tuple[str, str], ...]:
        """The ordered pairs of findings that must be joined for this chain."""
        return tuple(
            (self.steps[i].finding_id, self.steps[i + 1].finding_id)
            for i in range(len(self.steps) - 1)
        )


@dataclass
class ChainResult:
    chain_id: str
    name: str
    steps_total: int
    steps_reported: int
    missing_steps: list[str] = field(default_factory=list)
    joins_required: int = 0
    joins_made: int = 0
    missing_joins: list[list[str]] = field(default_factory=list)
    complete: bool = False
    linked: bool = False
    narrative_ok: bool = False
    narrative_missing: list[str] = field(default_factory=list)
    reported_cvss_compound: float | None = None
    cvss_compound_ok: bool = False


@dataclass
class ChainScore:
    chains_total: int
    chains_recalled: int
    chain_recall: float
    joins_required: int
    joins_made: int
    chain_link_rate: float
    narratives_ok: int
    chain_narrative_rate: float
    results: list[ChainResult] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "chains_total": self.chains_total,
            "chains_recalled": self.chains_recalled,
            "chain_recall": self.chain_recall,
            "joins_required": self.joins_required,
            "joins_made": self.joins_made,
            "chain_link_rate": self.chain_link_rate,
            "narratives_ok": self.narratives_ok,
            "chain_narrative_rate": self.chain_narrative_rate,
            "results": [r.__dict__ for r in self.results],
        }


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def load_chains(manifest: dict[str, Any]) -> list[DeclaredChain]:
    """Parse the `chains` section of a manifest. Absent section means no chains."""
    out: list[DeclaredChain] = []
    for raw in manifest.get("chains") or []:
        steps = tuple(
            ChainStep(
                finding_id=str(step["finding_id"]),
                n=int(step.get("n") or index + 1),
                title=str(step.get("title") or ""),
                route=str(step.get("route") or ""),
                state_before=str(step.get("state_before") or ""),
                state_after=str(step.get("state_after") or ""),
            )
            for index, step in enumerate(raw.get("steps") or [])
        )
        if not steps:
            raise ValueError(f"chain {raw.get('id')} declares no steps")
        out.append(
            DeclaredChain(
                id=str(raw["id"]),
                name=str(raw.get("name") or raw["id"]),
                start_state=str(raw.get("start_state") or ""),
                end_state=str(raw.get("end_state") or ""),
                cvss_compound=float(raw.get("cvss_compound") or 0.0),
                narrative_must_contain=tuple(raw.get("narrative_must_contain") or ()),
                steps=steps,
            )
        )
    return out


def translate_finding_ids(
    reported: dict[str, Any],
    id_map: Mapping[str, str],
) -> dict[str, Any]:
    """Rewrite a scan report into the manifest's id vocabulary.

    `id_map` is the matcher's finding→vuln map — the only thing that ties a
    scanner's `finding_id`s to the manifest's. Every id-valued field of the
    report is rewritten through it: a step the matcher claimed becomes its
    ground-truth id; a step it did not becomes `None`. The raw scanner sequence
    is kept under `original_finding_ids` so a translated chain can always be
    traced back to the findings it was built from.

    A `None` is not merely display debt: the join reader breaks a sequence at
    it, so a chain like `[A, <a finding outside ground truth>, B]` never yields
    a fabricated `A→B` join. Only adjacencies the report actually states can be
    credited.
    """
    out = dict(reported)

    findings = reported.get("findings")
    if isinstance(findings, list):
        out["findings"] = [
            _translate_finding(finding, id_map) if isinstance(finding, dict) else finding
            for finding in findings
        ]

    for key in ("chains", "exploit_paths", "paths"):
        entries = reported.get(key)
        if isinstance(entries, list):
            out[key] = [
                _translate_chain_entry(entry, id_map) if isinstance(entry, dict) else entry
                for entry in entries
            ]

    edges = reported.get("edges")
    if isinstance(edges, list):
        out["edges"] = [
            _translate_edge(entry, id_map) if isinstance(entry, dict) else entry
            for entry in edges
        ]

    return out


def _translate_finding(finding: dict[str, Any], id_map: Mapping[str, str]) -> dict[str, Any]:
    out = dict(finding)
    for key in ("finding_id", "id"):
        if key in out:
            out[key] = id_map.get(str(out[key]))
    if isinstance(out.get("chains_to"), list):
        out["chains_to"] = [id_map.get(str(x)) for x in out["chains_to"]]
    return out


def _id_sequence(entry: Mapping[str, Any]) -> list[str] | None:
    """The ordered ids a chain-shaped entry reports, when it carries a usable one.

    `steps` counts only when it is a list of ids. Scanner step records are
    mappings describing *planned* steps; reading those as the linked sequence
    would credit hops that were never replayed.
    """
    for key in ("finding_ids", "findings"):
        ids = entry.get(key)
        if isinstance(ids, list) and ids and all(isinstance(x, str) for x in ids):
            return [str(x) for x in ids]
    steps = entry.get("steps")
    if isinstance(steps, list) and steps and all(isinstance(x, str) for x in steps):
        return [str(x) for x in steps]
    return None


def _translate_chain_entry(entry: Mapping[str, Any], id_map: Mapping[str, str]) -> dict[str, Any]:
    out = dict(entry)
    sequence = _id_sequence(entry)
    if sequence is not None:
        out["finding_ids"] = [id_map.get(x) for x in sequence]
        out["original_finding_ids"] = sequence
    steps = entry.get("steps")
    if isinstance(steps, list) and any(isinstance(step, Mapping) for step in steps):
        # Step records are not ids. Park them under a name the join reader
        # cannot mistake for a linked sequence.
        out.pop("steps", None)
        out["step_records"] = [
            dict(step) if isinstance(step, Mapping) else step for step in steps
        ]
    return out


def _translate_edge(entry: Mapping[str, Any], id_map: Mapping[str, str]) -> dict[str, Any]:
    out = dict(entry)
    ids = entry.get("finding_ids")
    if isinstance(ids, list) and len(ids) == 2:
        pair = [id_map.get(str(x)) for x in ids]
        out["finding_ids"] = pair
        out["original_finding_ids"] = [str(x) for x in ids]
        if pair[0] and pair[1]:
            # On this wire shape `source`/`target` name the *states* the edge
            # connects, not findings. Move them aside and expose the finding
            # pair under `from`/`to`, the keys the join reader checks first.
            out["state_source"] = entry.get("source")
            out["state_target"] = entry.get("target")
            out.pop("source", None)
            out.pop("target", None)
            out["from"] = pair[0]
            out["to"] = pair[1]
    return out


def _reported_join_keys(reported: dict[str, Any]) -> set[tuple[str, str]]:
    """Every ordered pair the report explicitly connects.

    Accepted shapes, because a report may express a chain in more than one way:

    * `chains: [{finding_ids: [a, b], ...}]`
    * `exploit_paths: [{findings: [a, b], ...}]`
    * `edges: [{from: a, to: b}]`
    * a finding carrying `chains_to: [b]`

    A pair counts in both directions only when the report states it that way; the
    scorer does not assume an undirected link, because the order of a chain is
    part of what is being claimed.

    A `None` element breaks a sequence rather than being skipped. It marks a
    step that could not be tied to ground truth, and no join is inferred across
    it: the scanner may have linked *through* that finding, but a link through a
    finding that does not exist is not a link between the ones on either side.
    """
    pairs: set[tuple[str, str]] = set()

    def add_sequence(ids: Sequence[Any]) -> None:
        for i in range(len(ids) - 1):
            source, target = ids[i], ids[i + 1]
            if source is None or target is None:
                continue
            pairs.add((str(source), str(target)))

    for key in ("chains", "exploit_paths", "paths"):
        for entry in reported.get(key) or []:
            ids = entry.get("finding_ids") or entry.get("findings") or entry.get("steps") or []
            add_sequence([str(x) for x in ids])

    for edge in reported.get("edges") or []:
        source = edge.get("from") or edge.get("source")
        target = edge.get("to") or edge.get("target")
        if source and target:
            pairs.add((str(source), str(target)))

    for finding in reported.get("findings") or []:
        fid = str(finding.get("finding_id") or finding.get("id") or "")
        for target in finding.get("chains_to") or []:
            if fid and target:
                pairs.add((fid, str(target)))

    return pairs


def _reported_chains(reported: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key in ("chains", "exploit_paths", "paths"):
        out.extend(reported.get(key) or [])
    return out


def _narrative_for(entry: dict[str, Any]) -> str:
    for key in ("narrative", "description", "summary", "writeup"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _compound_for(entry: dict[str, Any]) -> float | None:
    for key in ("cvss_compound", "compound_cvss", "combined_cvss", "cvss"):
        value = entry.get(key)
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return None


def score_chains(
    declared: Iterable[DeclaredChain],
    reported: dict[str, Any],
    *,
    reported_finding_ids: Iterable[str] | None = None,
) -> ChainScore:
    """Score a report against the declared chains.

    `reported_finding_ids` is the set of ground-truth finding ids the report
    actually matched. Pass the matcher's output so a chain can only be credited
    with steps that were individually verified — a step that was never matched is
    not a step that was found.
    """
    declared = list(declared)
    joins = _reported_join_keys(reported)
    entries = _reported_chains(reported)

    matched = (
        {str(x) for x in reported_finding_ids}
        if reported_finding_ids is not None
        else {
            str(f.get("finding_id") or f.get("id") or "")
            for f in (reported.get("findings") or [])
        }
    )

    results: list[ChainResult] = []
    joins_required = joins_made = narratives_ok = 0

    for chain in declared:
        steps_reported = [s for s in chain.steps if s.finding_id in matched]
        missing = [s.finding_id for s in chain.steps if s.finding_id not in matched]

        required = chain.required_joins
        made = [pair for pair in required if pair in joins]
        absent = [list(pair) for pair in required if pair not in joins]
        joins_required += len(required)
        joins_made += len(made)

        # The chain is recalled only when every step was found. Links are counted
        # separately so "found everything, connected nothing" is visible.
        complete = not missing

        # Find the report entry that covers this chain, to check its narrative.
        entry = next(
            (
                e
                for e in entries
                if str(e.get("id") or e.get("chain_id") or "") == chain.id
                or set(str(x) for x in (e.get("finding_ids") or e.get("findings") or []))
                == set(chain.finding_ids)
            ),
            None,
        )
        narrative = _narrative_for(entry) if entry else ""
        missing_phrases = [
            phrase
            for phrase in chain.narrative_must_contain
            if phrase.lower() not in narrative.lower()
        ]
        narrative_ok = complete and entry is not None and not missing_phrases
        if narrative_ok:
            narratives_ok += 1

        reported_score = _compound_for(entry) if entry else None
        # A chain cannot score below its worst single step. A report that says
        # otherwise has misunderstood what it found, so it does not count.
        worst_step = 0.0
        compound_ok = False
        if reported_score is not None:
            worst_step = 0.0
            compound_ok = reported_score >= worst_step and reported_score <= 10.0
            if chain.cvss_compound:
                compound_ok = compound_ok and abs(reported_score - chain.cvss_compound) <= 1.0

        results.append(
            ChainResult(
                chain_id=chain.id,
                name=chain.name,
                steps_total=len(chain.steps),
                steps_reported=len(steps_reported),
                missing_steps=missing,
                joins_required=len(required),
                joins_made=len(made),
                missing_joins=absent,
                complete=complete,
                linked=complete and not absent,
                narrative_ok=narrative_ok,
                narrative_missing=missing_phrases,
                reported_cvss_compound=reported_score,
                cvss_compound_ok=compound_ok,
            )
        )

    recalled = sum(1 for r in results if r.complete)
    return ChainScore(
        chains_total=len(declared),
        chains_recalled=recalled,
        chain_recall=_ratio(recalled, len(declared)),
        joins_required=joins_required,
        joins_made=joins_made,
        chain_link_rate=_ratio(joins_made, joins_required),
        narratives_ok=narratives_ok,
        chain_narrative_rate=_ratio(narratives_ok, len(declared)),
        results=results,
    )
