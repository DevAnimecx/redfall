"""The BYOK backend: RedFall holds a provider key and calls a model API.

This is the 0.1.x behaviour, moved behind the `ReasoningBackend` seam with no
change in what it does. The test suite that covered `redfall.llm.LLM` covers
this class unchanged, which is the evidence that the seam is behaviour
preserving.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import select

from ..llm import (
    LLMError,
    LLMResult,
    _cost_usd,
    _response_content,
    _response_to_dict,
    model_for_tier,
)
from ..store.models import LLMCall, LLMResponse
from .backend import BackendError, BackendResult, ReasoningBackend


class LiteLLMBackend(ReasoningBackend):
    name = "litellm"

    def __init__(self, *, session_factory, budget) -> None:
        super().__init__(budget=budget)
        self._session_factory = session_factory

    def model_for_tier(self, tier: str) -> str:
        return model_for_tier(tier)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": "provider",
            "tiers": {t: model_for_tier(t) for t in ("fast", "mid", "deep")},
        }

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
        import litellm

        model = model_for_tier(tier)
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            kwargs["max_tokens"] = min(max_tokens, max(256, self.budget.remaining_tokens()))

        started = time.time()
        try:
            response = litellm.completion(**kwargs)
        except Exception as err:  # noqa: BLE001 - provider failures are reported, not hidden
            raise LLMError(
                f"{model} call failed at stage {stage!r}: {type(err).__name__}: {err}"
            ) from err
        latency_ms = int((time.time() - started) * 1000)

        raw = _response_to_dict(response)
        usage = raw.get("usage") or {}
        return BackendResult(
            content=_response_content(raw),
            model=model,
            backend=self.name,
            tier=tier,
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            cost_usd=_cost_usd(response) or 0.0,
            latency_ms=latency_ms,
            cached=False,
            raw=raw,
        )

    # -- transcript store, unchanged from 0.1.x ----------------------------
    def _lookup(self, digest: str) -> BackendResult | None:
        with self._session_factory() as session:
            row = session.execute(
                select(LLMResponse).where(LLMResponse.id == digest)
            ).scalar_one_or_none()
            if row is None:
                return None
            call = session.get(LLMCall, row.call_id)
            if call is None:
                return None
            if not row.content:
                return None
            self._record(
                digest=digest,
                scan_id=call.scan_id,
                branch_id=call.branch_id,
                stage=call.stage,
                tier=call.tier,
                messages=(row.request_json or {}).get("messages", []),
                temperature=float((row.request_json or {}).get("temperature", 0.2)),
                result=BackendResult(
                    content=row.content,
                    model=call.model,
                    backend=self.name,
                    tier=call.tier,
                    prompt_tokens=call.prompt_tokens,
                    completion_tokens=call.completion_tokens,
                    cost_usd=call.cost_usd,
                    latency_ms=0,
                    cached=True,
                    raw=row.response_json or {},
                ),
                reuse_of=row.id,
            )
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
        import hashlib

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
                            "model": result.model,
                            "tier": tier,
                            "temperature": temperature,
                            "messages": messages,
                        },
                        response_json=result.raw,
                        content=result.content,
                    )
                )
        return call_id


#: `LLMResult` stays importable from here for the callers that still name it.
__all__ = ["LiteLLMBackend", "LLMResult", "BackendError"]
