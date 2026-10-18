"""The reasoning stages: plan, analyse, generate a PoC, propose a fix.

Every stage is a real provider call through `redfall.llm`. A stage that cannot
get a usable answer raises; none of them substitute a default, because a default
here would be a fabricated finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..llm import JSONParseError, LLM, LLMResult
from . import categories

PROMPT_DIR = Path(__file__).parent / "prompts"

MAX_CONTEXT_CHARS = 24000


@lru_cache(maxsize=None)
def load_prompt(name: str) -> str:
    """Read a prompt template from the package directory."""
    path = PROMPT_DIR / f"{name}.md"
    if not path.exists():
        raise FileNotFoundError(f"missing prompt template: {path}")
    common = (PROMPT_DIR / "_common.md").read_text()
    return f"{common.strip()}\n\n{path.read_text().strip()}\n"


def _system(stage: str) -> str:
    return load_prompt(stage)


def _clip(text: str, limit: int = MAX_CONTEXT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n…[truncated {len(text) - limit} chars]"


@dataclass
class PlannedBranch:
    name: str
    type: str
    scope_files: list[str]
    scope_routes: list[str]
    priority: int
    model_tier: str
    rationale: str

    @classmethod
    def from_json(cls, data: dict[str, Any], index: int) -> "PlannedBranch":
        return cls(
            name=str(data.get("name") or f"branch-{index + 1}"),
            type=str(data.get("type") or "static"),
            scope_files=[str(f) for f in (data.get("scope_files") or [])],
            scope_routes=[str(r) for r in (data.get("scope_routes") or [])],
            # Priority is higher-first. When the planner does not answer, the
            # order it listed the branches in is the best available estimate.
            priority=int(data.get("priority") or (100 - index)),
            model_tier=str(data.get("model_tier") or "mid"),
            rationale=str(data.get("rationale") or ""),
        )


@dataclass
class AnalysisFinding:
    category: str
    severity: str
    title: str
    description: str
    file: str
    line: int
    symbol: str
    poc: dict[str, Any]
    evidence: str
    remediation: str

    @property
    def dedupe_key(self) -> str:
        return f"{self.category}:{self.file}:{self.symbol or self.line}"


class Agent:
    """Wraps the LLM with the domain context each stage needs."""

    def __init__(self, llm: LLM, scan_id: str) -> None:
        self.llm = llm
        self.scan_id = scan_id

    # -- stage 1: planning -------------------------------------------------
    def plan(
        self,
        routes: list[dict[str, Any]],
        taints: list[dict[str, Any]],
        dependencies: list[dict[str, Any]],
    ) -> list[PlannedBranch]:
        user = json.dumps(
            {
                "route_inventory": routes,
                "taint_paths": taints,
                "installed_dependencies": dependencies,
                "categories_in_scope": categories.all_keys(),
            },
            indent=2,
        )
        data, _result = self.llm.complete_json(
            messages=[
                {"role": "system", "content": _system("planner")},
                {"role": "user", "content": _clip(user)},
            ],
            stage="plan",
            scan_id=self.scan_id,
            tier="mid",
            temperature=0.2,
            schema_hint='{"branches":[{"name","type","scope_files","scope_routes","priority","model_tier","rationale"}]}',
        )
        raw_branches = data.get("branches") if isinstance(data, dict) else None
        if not isinstance(raw_branches, list):
            raise JSONParseError(json.dumps(data), "planner returned no `branches` list")

        branches = [PlannedBranch.from_json(b, i) for i, b in enumerate(raw_branches) if isinstance(b, dict)]
        if not branches:
            raise JSONParseError(json.dumps(data), "planner returned an empty `branches` list")
        return branches

    # -- stage 2: analysis -------------------------------------------------
    def analyse(
        self,
        *,
        branch_id: str,
        branch_name: str,
        files: dict[str, str],
        routes: list[dict[str, Any]],
        taints: list[dict[str, Any]],
        dependencies: list[dict[str, Any]],
        tier: str = "mid",
    ) -> list[AnalysisFinding]:
        sources = "\n\n".join(
            f"===== {path} =====\n{self._numbered(content)}" for path, content in files.items()
        )
        user = json.dumps(
            {
                "branch": branch_name,
                "routes": routes,
                "taint_paths": taints,
                "installed_dependencies": dependencies,
                "categories_in_scope": categories.all_keys(),
            },
            indent=2,
        )
        data, _result = self.llm.complete_json(
            messages=[
                {"role": "system", "content": _system("analyzer")},
                {"role": "user", "content": _clip(user, 8000)},
                {"role": "user", "content": f"Source under analysis:\n\n{_clip(sources)}"},
            ],
            stage="analyze",
            scan_id=self.scan_id,
            branch_id=branch_id,
            tier=tier,
            temperature=0.2,
        )
        raw = data.get("findings") if isinstance(data, dict) else None
        if raw is None:
            raise JSONParseError(json.dumps(data), "analyzer returned no `findings` key")
        if not isinstance(raw, list):
            raise JSONParseError(json.dumps(data), "analyzer `findings` was not a list")

        findings: list[AnalysisFinding] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            loc = item.get("location") or {}
            findings.append(
                AnalysisFinding(
                    category=categories.normalise(str(item.get("category") or "")),
                    severity=str(item.get("severity") or "medium"),
                    title=str(item.get("title") or ""),
                    description=str(item.get("description") or ""),
                    file=str(loc.get("file") or ""),
                    line=int(loc.get("line") or 0),
                    symbol=str(loc.get("symbol") or ""),
                    poc=item.get("poc") if isinstance(item.get("poc"), dict) else {},
                    evidence=str(item.get("evidence") or ""),
                    remediation=str(item.get("remediation") or ""),
                )
            )
        return findings

    # -- stage 3: PoC generation ------------------------------------------
    def generate_poc(
        self,
        *,
        branch_id: str | None,
        finding: AnalysisFinding,
        source_snippet: str,
        route: dict[str, Any] | None,
        prior_attempt: dict[str, Any] | None = None,
        tier: str = "deep",
    ) -> tuple[dict[str, Any], str]:
        payload: dict[str, Any] = {
            "finding": {
                "category": finding.category,
                "title": finding.title,
                "description": finding.description,
                "location": {"file": finding.file, "line": finding.line, "symbol": finding.symbol},
                "evidence": finding.evidence,
            },
            "route": route,
            "category_definition": {
                "proof_required": (categories.get(finding.category).proof if categories.get(finding.category) else ""),
            },
        }
        if prior_attempt is not None:
            payload["previous_attempt"] = prior_attempt

        messages = [
            {"role": "system", "content": _system("poc_generator")},
            {"role": "user", "content": _clip(json.dumps(payload, indent=2), 8000)},
            {"role": "user", "content": f"Source around the vulnerability:\n\n{_clip(source_snippet)}"},
        ]
        data, _result = self.llm.complete_json(
            messages=messages,
            stage="poc",
            scan_id=self.scan_id,
            branch_id=branch_id,
            tier=tier,
            temperature=0.3,
        )
        poc = data.get("poc") if isinstance(data, dict) else None
        if not isinstance(poc, dict) or "request" not in poc:
            raise JSONParseError(json.dumps(data), "poc generator returned no `poc.request`")
        reasoning = str(data.get("reasoning") or "")
        return poc, reasoning

    # -- stage 4: chain proposal ------------------------------------------
    def propose_chains(
        self,
        *,
        findings: list[dict[str, Any]],
        max_chains: int,
    ) -> list[dict[str, Any]]:
        """Ask the model which reproduced findings can be wired together.

        The answer is a proposal, not a result: every chain it names is replayed
        in the sandbox before anything about it is believed.
        """
        user = json.dumps({"reproduced_findings": findings, "max_chains": max_chains}, indent=2)
        data, _result = self.llm.complete_json(
            messages=[
                {"role": "system", "content": _system("chain_analyst")},
                {"role": "user", "content": _clip(user)},
            ],
            stage="chain",
            scan_id=self.scan_id,
            tier="deep",
            temperature=0.2,
            schema_hint=(
                '{"chains":[{"title","rationale","steps":[{"finding_id","state_before",'
                '"state_after","description","expect_expr","extract","setup","followup"}]}]}'
            ),
        )
        raw = data.get("chains") if isinstance(data, dict) else None
        if raw is None:
            raise JSONParseError(json.dumps(data), "chain analyst returned no `chains` key")
        if not isinstance(raw, list):
            raise JSONParseError(json.dumps(data), "chain analyst `chains` was not a list")
        return [item for item in raw if isinstance(item, dict)]

    # -- stage 5: fix proposal ---------------------------------------------
    def propose_fix(
        self,
        *,
        finding: AnalysisFinding,
        file_source: str,
        tests: dict[str, str],
        dependencies: list[dict[str, Any]],
        verify_feedback: str | None = None,
    ) -> dict[str, Any]:
        test_text = "\n\n".join(
            f"===== {path} =====\n{self._numbered(content)}" for path, content in tests.items()
        )
        payload: dict[str, Any] = {
            "finding": {
                "category": finding.category,
                "title": finding.title,
                "location": {"file": finding.file, "line": finding.line, "symbol": finding.symbol},
                "remediation_hint": finding.remediation,
            },
            "installed_dependencies": dependencies,
        }
        if verify_feedback:
            payload["previous_verification_failure"] = verify_feedback

        data, _result = self.llm.complete_json(
            messages=[
                {"role": "system", "content": _system("fixer")},
                {"role": "user", "content": _clip(json.dumps(payload, indent=2), 4000)},
                {"role": "user", "content": f"Affected file {finding.file}:\n\n{self._numbered(file_source)}"},
                {"role": "user", "content": f"Tests that must stay green:\n\n{_clip(test_text)}"},
            ],
            stage="fix",
            scan_id=self.scan_id,
            tier="deep",
            temperature=0.1,
        )
        if not isinstance(data, dict):
            raise JSONParseError(json.dumps(data), "fixer did not return an object")
        return {
            "patch": str(data.get("patch") or ""),
            "strategy": str(data.get("strategy") or ""),
            "explanation": str(data.get("explanation") or ""),
            "blocker": data.get("blocker"),
        }

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _numbered(source: str) -> str:
        """Prefix every line with its 1-based number so citations are checkable."""
        width = len(str(source.count("\n") + 1))
        return "\n".join(
            f"{i + 1:>{width}}| {line}" for i, line in enumerate(source.splitlines())
        )


def snippet_for(result: Any, rel_path: str, line: int, radius: int = 40) -> str:
    """Numbered source window around a finding, for prompt context."""
    for f in result.files:
        if f.path != rel_path:
            continue
        lines = f.content.splitlines()
        start = max(0, line - radius - 1)
        end = min(len(lines), line + radius)
        width = len(str(len(lines)))
        return "\n".join(
            f"{i + 1:>{width}}| {lines[i]}" for i in range(start, end)
        )
    return ""
