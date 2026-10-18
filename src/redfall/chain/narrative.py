"""The written account of a chain.

A chain finding has to say, in order, what the attacker does at each step, why
each step follows from the last, and what the end state is worth. The narrative
is generated from the graph edges and the findings behind them — never written
freehand — so it cannot drift from the evidence.

Every generated narrative is checked against the manifest's
`narrative_must_contain` before it is accepted as a passing result.
"""

from __future__ import annotations

from typing import Sequence

from .graph import AttackGraph, Edge

STATE_PHRASE = {
    "none": "no access",
    "user_creds": "valid low-privilege credentials",
    "admin_creds": "administrative credentials",
    "session_token": "another user's live session token",
    "db_read": "the ability to read rows they are not entitled to",
    "db_write": "the ability to write arbitrary rows",
    "file_read": "the ability to read files outside the intended root",
    "file_write": "the ability to write files to the server",
    "secret": "a secret taken from the application",
    "code_exec": "code execution in the application's own context",
    "ssrf_reach": "the ability to make the server issue requests of the attacker's choosing",
}


def state_phrase(key: str) -> str:
    kind, _, resource = key.partition(":")
    phrase = STATE_PHRASE.get(kind, kind.replace("_", " "))
    if resource and resource != "*":
        return f"{phrase} on `{resource}`"
    return phrase


def narrate(graph: AttackGraph, chain: Sequence[Edge], findings: dict[str, dict]) -> str:
    """Render a chain as ordered prose the reader can act on."""
    if not chain:
        return ""

    lines = [
        f"### Chain: {state_phrase(chain[0].source)} → {state_phrase(chain[-1].target)}",
        "",
    ]

    scores = graph.chain_scores(list(chain))
    from .cvss_compound import chain_severity, compound_cvss, uplift_over_worst_hop

    base, modifiers = scores
    score = compound_cvss(base, modifiers)
    worst = max(base) if base else 0.0

    for index, edge in enumerate(chain, start=1):
        title = edge.description or f"step {index}"
        lines.append(f"{index}. **{title}**")
        lines.append(f"   - From: {state_phrase(edge.source)}")
        lines.append(f"   - To: {state_phrase(edge.target)}")
        lines.append(f"   - Proven by: {', '.join(edge.finding_ids)}")
        lines.append(f"   - Branch: `{edge.branch_id}`")
        for fid in edge.finding_ids:
            finding = findings.get(fid)
            if not finding:
                continue
            lines.append(
                f"   - {fid}: {finding.get('title', 'untitled')} "
                f"(CVSS {finding.get('cvss_score')}, {finding.get('severity', 'unknown')})"
            )
        lines.append("")

    lines.extend(
        [
            f"**Combined severity:** {score} ({chain_severity(score)}). "
            f"Worst single step is {worst}; the chain is "
            f"{uplift_over_worst_hop(base, score):+.2f} on top of it.",
            "",
            f"**Steps:** {len(chain)}. **Distinct findings:** {len({f for e in chain for f in e.finding_ids})}.",
            "",
        ]
    )
    return "\n".join(lines)


def check_narrative(narrative: str, must_contain: Sequence[str]) -> tuple[bool, list[str]]:
    """Verify a narrative against the manifest's required phrases.

    Returns (ok, missing). Case-insensitive, because the requirement is that the
    reader is told the fact, not that the capitalisation matches.
    """
    lowered = narrative.lower()
    missing = [phrase for phrase in must_contain if phrase.lower() not in lowered]
    return not missing, missing
