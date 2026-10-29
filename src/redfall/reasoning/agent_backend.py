"""A ReasoningBackend backed by an installed agent (0.2.2).

This is the piece that makes "no AI API key" real. It turns the engine's
messages into one prompt, hands it to a driver, and records the transcript in
the same tables the LiteLLM path uses — so a finding produced by Claude Code and
a finding produced by gpt-4o are auditable in exactly the same way.

The transcript is the point. A backend that ran an agent and kept no record
would be a backend whose findings nobody can replay, which is the thing the
no-mock contract exists to prevent.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from sqlalchemy import select

from ..agents.driver import AgentDriver, AgentError
from ..store.models import LLMCall, LLMResponse
from .backend import BackendError, BackendResult, ReasoningBackend

#: How the engine's role-tagged messages are flattened into one prompt.
_SYSTEM_HEADER = "SYSTEM INSTRUCTIONS"
_USER_HEADER = "REQUEST"


def flatten_messages(messages: list[dict[str, str]]) -> str:
    """Turn role-tagged messages into one prompt an agent CLI can take.

    System messages lead; user/assistant turns follow in order. The shape is
    explicit so a driver never has to guess which part is instruction and which
    is target source.
    """
    system_parts: list[str] = []
    turns: list[str] = []
    for message in messages:
        role = str(message.get("role") or "user")
        content = str(message.get("content") or "")
        if role == "system":
            system_parts.append(content)
        elif role == "assistant":
            turns.append(f"--- your previous reply ---\n{content}")
        else:
            turns.append(content)

    blocks: list[str] = []
    if system_parts:
        blocks.append(f"# {_SYSTEM_HEADER}\n" + "\n\n".join(system_parts))
    blocks.append(f"# {_USER_HEADER}\n" + "\n\n".join(turns))
    return "\n\n".join(blocks)


class AgentBackend(ReasoningBackend):
    """Reasoning borrowed from an agent CLI or a custom command."""

    def __init__(self, driver: AgentDriver, *, session_factory, budget, timeout_s: int = 300) -> None:
        super().__init__(budget=budget)
        self.driver = driver
        self.name = f"agent:{driver.name}"
        self._session_factory = session_factory
        self._timeout_s = timeout_s

    def model_for_tier(self, tier: str) -> str:
        """Agents pick their own model, so the tier is part of the identity.

        Naming the tier keeps the transcript cache honest: asking the same
        prompt at `fast` and at `deep` is two different requests.
        """
        return f"{self.driver.name}:{tier}"

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": "agent",
            "driver": self.driver.name,
            "title": self.driver.title,
            "installed": self.driver.available(),
            "version": self.driver.version() if self.driver.available() else None,
        }

    def available(self) -> bool:
        return self.driver.available()

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
        prompt = flatten_messages(messages)
        model = None
        env_model = _env_model_for_tier(tier)
        if env_model:
            model = env_model

        started = time.time()
        try:
            invocation = self.driver.invoke(prompt, model=model, timeout_s=self._timeout_s)
        except AgentError as err:
            raise BackendError(f"{self.driver.name} failed at stage {stage!r}: {err}") from err
        latency_ms = int((time.time() - started) * 1000) or invocation.duration_ms

        return BackendResult(
            content=invocation.text,
            model=model or self.driver.name,
            backend=self.name,
            tier=tier,
            prompt_tokens=invocation.prompt_tokens or _approx_tokens(prompt),
            completion_tokens=invocation.completion_tokens or _approx_tokens(invocation.text),
            cost_usd=invocation.cost_usd or 0.0,
            latency_ms=latency_ms,
            cached=False,
            raw={
                "agent": self.driver.name,
                "argv": invocation.argv,
                "exit_code": invocation.exit_code,
                "stderr": invocation.stderr[:2000],
            },
        )

    # -- transcript, same tables as LiteLLM -------------------------------
    def _lookup(self, digest: str) -> BackendResult | None:
        if self._session_factory is None:
            return None
        with self._session_factory() as session:
            row = session.execute(
                select(LLMResponse).where(LLMResponse.id == digest)
            ).scalar_one_or_none()
            if row is None or not row.content:
                return None
            call = session.get(LLMCall, row.call_id)
            if call is None:
                return None
            return BackendResult(
                content=row.content,
                model=call.model,
                backend=self.name,
                tier=call.tier,
                prompt_tokens=call.prompt_tokens,
                completion_tokens=call.completion_tokens,
                cost_usd=call.cost_usd,
                latency_ms=0,
                cached=True,
                call_id=call.id,
                raw=row.response_json or {},
            )

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
        reuse_of: str | None = None,
    ) -> str:
        if self._session_factory is None:
            return digest
        call_id = hashlib.sha256(
            f"{digest}:{stage}:{scan_id}:{time.time_ns()}".encode()
        ).hexdigest()[:16]
        with self._session_factory() as session:
            session.add(
                LLMCall(
                    id=call_id,
                    scan_id=scan_id,
                    branch_id=branch_id,
                    stage=stage,
                    tier=tier,
                    model=result.model,
                    prompt_tokens=result.prompt_tokens,
                    completion_tokens=result.completion_tokens,
                    cost_usd=result.cost_usd,
                    latency_ms=result.latency_ms,
                    cached=result.cached,
                    request_hash=digest,
                )
            )
            if reuse_of is None:
                session.add(
                    LLMResponse(
                        id=digest,
                        call_id=call_id,
                        request_json={
                            "backend": self.name,
                            "agent": self.driver.name,
                            "tier": tier,
                            "temperature": temperature,
                            "messages": messages,
                        },
                        response_json=result.raw,
                        content=result.content,
                    )
                )
        return call_id


def _env_model_for_tier(tier: str) -> str | None:
    import os

    return os.getenv(f"REDFALL_AGENT_MODEL_{tier.upper()}")


def _approx_tokens(text: str) -> int:
    """Rough token count for agents that report none. Labelled as estimated."""
    return max(1, len(text) // 4)


__all__ = ["AgentBackend", "flatten_messages"]
