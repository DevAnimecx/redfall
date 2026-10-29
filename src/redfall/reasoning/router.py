"""Multi-agent routing and consensus (0.2.8).

A router holds several backends and decides which one answers each request:

* **by tier** — `fast` work can go to a cheap or local agent, `deep` work to the
  strongest one. Classifying a file is not the same job as proposing a chain.
* **by capability** — the router asks each candidate whether it can take the
  prompt before choosing it.
* **consensus** — the same prompt goes to N agents and a finding survives only
  where at least `min_agree` agree. Agreement is a *prior*, never proof: the
  caller still executes the result in the sandbox. Consensus reduces wasted
  sandbox time and never replaces verification.

A router with no candidates that can answer raises; it does not quietly fall
back to something weaker, because that would make a scan's quality depend on
which agents happened to be installed.
"""

from __future__ import annotations

from typing import Any, Callable

from .backend import BackendError, BackendResult, ReasoningBackend
from .config import BackendConfig


class RouterBackend(ReasoningBackend):
    name = "router"

    def __init__(
        self,
        config: BackendConfig,
        *,
        session_factory,
        budget,
        build: Callable[..., ReasoningBackend],
    ) -> None:
        super().__init__(budget=budget)
        self._build = build
        self._by_tier: dict[str, ReasoningBackend] = {}
        self._fallback: ReasoningBackend | None = None
        self._consensus_agents: list[str] = []
        self._min_agree = 1

        for tier, spec in (config.routes or {}).items():
            if not isinstance(spec, dict):
                raise BackendError(f"route {tier!r} must be a table")
            self._by_tier[tier] = build(
                BackendConfig(**{**spec, "source": config.source}),
                session_factory=session_factory,
                budget=budget,
            )

        consensus = config.consensus or {}
        self._consensus_agents = [str(a) for a in (consensus.get("agents") or [])]
        self._min_agree = int(consensus.get("min_agree") or 1)
        self._session_factory = session_factory
        self._config = config

        if not self._by_tier and not self._consensus_agents:
            raise BackendError(
                "router backend needs at least one of [routes] or [consensus] in redfall.toml"
            )

    # -- selection ---------------------------------------------------------
    def model_for_tier(self, tier: str) -> str:
        backend = self._by_tier.get(tier) or self._any_route()
        return backend.model_for_tier(tier) if backend else f"router:{tier}"

    def _any_route(self) -> ReasoningBackend | None:
        if self._fallback is not None:
            return self._fallback
        if self._by_tier:
            # Prefer `mid` as the general-purpose route when a tier is unset.
            self._fallback = self._by_tier.get("mid") or next(iter(self._by_tier.values()))
        return self._fallback

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": "router",
            "routes": {t: b.describe() for t, b in self._by_tier.items()},
            "consensus_agents": self._consensus_agents,
            "min_agree": self._min_agree,
        }

    def available(self) -> bool:
        if self._consensus_agents:
            return True
        return self._any_route() is not None

    def _route_for(self, tier: str) -> ReasoningBackend:
        backend = self._by_tier.get(tier) or self._any_route()
        if backend is None:
            raise BackendError(f"router has no backend for tier {tier!r}")
        return backend

    # -- invocation --------------------------------------------------------
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
        if self._consensus_agents:
            return self._invoke_consensus(
                messages=messages, stage=stage, tier=tier, temperature=temperature,
                max_tokens=max_tokens, scan_id=scan_id, branch_id=branch_id,
            )
        backend = self._route_for(tier)
        result = backend._invoke(
            messages=messages, stage=stage, tier=tier, temperature=temperature,
            max_tokens=max_tokens, scan_id=scan_id, branch_id=branch_id,
        )
        # Record the sub-backend's identity so a report names the agent that
        # actually answered, not just "router".
        result.backend = backend.name
        return result

    def _invoke_consensus(
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
        from ..agents.registry import driver_registry
        from .agent_backend import AgentBackend

        registry = driver_registry()
        attempts: list[tuple[str, BackendResult]] = []
        errors: list[str] = []
        for name in self._consensus_agents:
            driver = registry.get(name)
            if driver is None or not driver.available():
                errors.append(f"{name}: not installed")
                continue
            backend = AgentBackend(
                driver, session_factory=self._session_factory, budget=self.budget
            )
            try:
                result = backend._invoke(
                    messages=messages, stage=stage, tier=tier, temperature=temperature,
                    max_tokens=max_tokens, scan_id=scan_id, branch_id=branch_id,
                )
            except BackendError as err:
                errors.append(f"{name}: {err}")
                continue
            attempts.append((name, result))

        if not attempts:
            raise BackendError(
                "consensus found no agent that could answer: " + "; ".join(errors or ["none configured"])
            )

        import json

        from ..llm import extract_json

        # Group answers by their parsed JSON, so agreement is judged on meaning
        # rather than on whitespace.
        buckets: dict[str, list[tuple[str, BackendResult]]] = {}
        for name, result in attempts:
            try:
                key = json.dumps(extract_json(result.content), sort_keys=True)
            except Exception:  # noqa: BLE001 - an unparseable answer cannot agree
                key = f"__unparsed__{name}"
            buckets.setdefault(key, []).append((name, result))

        best_key, best = max(buckets.items(), key=lambda kv: len(kv[1]))
        if len(best) < self._min_agree:
            raise BackendError(
                f"consensus failed: the best {len(best)} of {len(attempts)} agents agreed, "
                f"which is below min_agree={self._min_agree}"
            )

        winner_name, winner = best[0]
        return BackendResult(
            content=winner.content,
            model=winner.model,
            backend=f"consensus:{'+'.join(n for n, _ in best)}",
            tier=tier,
            prompt_tokens=sum(r.prompt_tokens for _, r in attempts),
            completion_tokens=sum(r.completion_tokens for _, r in attempts),
            cost_usd=sum(r.cost_usd for _, r in attempts),
            latency_ms=max(r.latency_ms for _, r in attempts),
            cached=False,
            raw={
                "consensus": {
                    "winner": winner_name,
                    "agreed": [n for n, _ in best],
                    "considered": [n for n, _ in attempts],
                    "errors": errors,
                    "min_agree": self._min_agree,
                }
            },
        )


__all__ = ["RouterBackend"]
