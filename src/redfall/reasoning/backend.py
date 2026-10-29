"""The reasoning seam (0.2.1).

Every stage of the engine reasons through exactly one interface: a
`ReasoningBackend`. It has two implementations today and they are two ways of
answering the same question:

* `LiteLLMBackend` — RedFall holds a provider key and calls a model API.
* `AgentDriver` — RedFall holds no key and borrows the reasoning of an agent
  the operator already runs (Claude Code, Codex, an editor agent, ...).

The split exists so that "works without an AI API key" is not a degraded mode
with its own code path. It is the same call, answered by a different backend.

The contract is deliberately small. A backend must be able to:

1. answer one prompt and return the text (`complete`);
2. report what it has spent so far and refuse when the budget is gone;
3. leave a transcript a report can cite.

`complete_json` and the JSON repair loop are defined once, on the base class, so
every backend inherits identical parse-and-repair behaviour. A backend that
produced different JSON discipline per transport would make findings depend on
which agent the operator happened to have installed.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..llm import (
    MAX_JSON_REPAIRS,
    Budget,
    BudgetExceeded,
    JSONParseError,
    LLMError,
    extract_json,
)


@dataclass
class BackendResult:
    """One answer from a backend, with the accounting the report needs."""

    content: str
    model: str
    backend: str
    tier: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: int = 0
    cached: bool = False
    call_id: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class BackendError(LLMError):
    """A backend could not answer, for a reason the caller can act on."""


def request_digest(model: str, tier: str, messages: list[dict[str, str]], temperature: float) -> str:
    payload = json.dumps(
        {"model": model, "tier": tier, "temperature": temperature, "messages": messages},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ReasoningBackend(ABC):
    """The only way the engine reaches a model or an agent.

    Subclasses implement `_invoke`. Everything else — the budget check, the
    transcript record, the JSON repair loop — is shared and must not be
    reimplemented, so that a finding looks the same in the report no matter
    which backend produced it.
    """

    #: Short, stable identifier used in the report and in `redfall agent list`.
    name: str = "backend"

    def __init__(self, *, budget: Budget) -> None:
        self.budget = budget

    # -- subclass surface --------------------------------------------------
    @abstractmethod
    def _invoke(
        self,
        *,
        messages: list[dict[str, str]],
        stage: str,
        tier: str,
        temperature: float,
        max_tokens: int | None,
        scan_id: str,
        branch_id: str | None,
    ) -> BackendResult:
        """Answer one prompt. Must be a real call; must not fabricate."""

    @abstractmethod
    def model_for_tier(self, tier: str) -> str:
        """The model or agent handle this backend would use for a tier."""

    def describe(self) -> dict[str, Any]:
        """Facts about this backend for the report and for diagnostics."""
        return {"name": self.name, "kind": "backend"}

    def available(self) -> bool:
        """True when the backend can actually answer right now."""
        return True

    # -- shared behaviour --------------------------------------------------
    def complete(
        self,
        *,
        messages: list[dict[str, str]],
        stage: str,
        scan_id: str,
        branch_id: str | None = None,
        tier: str = "mid",
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> BackendResult:
        """One real call, budgeted before and checked after.

        The budget is enforced before the call so an over-budget campaign fails
        rather than silently truncating — the same rule §5 set for the LiteLLM
        path, now applied uniformly to agents.
        """
        digest = request_digest(self.model_for_tier(tier), tier, messages, temperature)

        cached = self._lookup(digest)
        if cached is not None:
            self.budget.add(cached.prompt_tokens, cached.completion_tokens, cached.cost_usd)
            self.budget.check()
            return cached

        self.budget.check()

        result = self._invoke(
            messages=messages,
            stage=stage,
            tier=tier,
            temperature=temperature,
            max_tokens=max_tokens,
            scan_id=scan_id,
            branch_id=branch_id,
        )

        self.budget.add(result.prompt_tokens, result.completion_tokens, result.cost_usd)
        self.budget.check()

        result.call_id = self._record(
            digest=digest,
            scan_id=scan_id,
            branch_id=branch_id,
            stage=stage,
            tier=tier,
            messages=messages,
            temperature=temperature,
            result=result,
        )
        return result

    def complete_json(
        self,
        *,
        messages: list[dict[str, str]],
        stage: str,
        scan_id: str,
        branch_id: str | None = None,
        tier: str = "mid",
        temperature: float = 0.2,
        max_tokens: int | None = None,
        schema_hint: str = "",
    ) -> tuple[Any, BackendResult]:
        """Complete and parse JSON, re-prompting on malformed output.

        Identical to the LiteLLM path's loop: the repair attempts are real calls,
        recorded like any other; if the backend never produces valid JSON this
        raises rather than inventing a default.
        """
        working = list(messages)
        for attempt in range(MAX_JSON_REPAIRS + 1):
            result = self.complete(
                messages=working,
                stage=stage,
                scan_id=scan_id,
                branch_id=branch_id,
                tier=tier,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            try:
                return extract_json(result.content), result
            except JSONParseError as err:
                if attempt == MAX_JSON_REPAIRS:
                    raise
                working = working + [
                    {"role": "assistant", "content": result.content},
                    {
                        "role": "user",
                        "content": (
                            f"Your previous reply was not valid JSON ({err.reason}). "
                            "Reply with a single JSON value and nothing else — no prose, "
                            "no markdown fences."
                            + (f"\nRequired shape:\n{schema_hint}" if schema_hint else "")
                        ),
                    },
                ]
        raise BackendError("unreachable: JSON repair loop exited without a result") from None

    # -- transcript (overridden by backends that persist) -------------------
    def _lookup(self, digest: str) -> BackendResult | None:
        """Exact-match cache. Backends without a store return None."""
        return None

    def _record(
        self,
        *,
        digest: str,
        scan_id: str,
        branch_id: str | None,
        stage: str,
        tier: str,
        messages: list[dict[str, str]],
        temperature: float,
        result: BackendResult,
    ) -> str:
        """Persist the transcript. Backends without a store return the digest."""
        return digest


__all__ = [
    "BackendError",
    "BackendResult",
    "BudgetExceeded",
    "ReasoningBackend",
    "request_digest",
]
