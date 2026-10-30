"""BYOK LLM access via LiteLLM (§5 model tiers, §1 rule 4 transcripts).

Hard rules implemented here:

* Every call is a live provider call. There is no offline or synthetic path.
* The verbatim request and response are persisted for every call, so nothing in
  a report rests on a transcript nobody can read.
* Repeating an identical prompt does not re-bill: the transcript table doubles
  as an exact-match cache keyed on model + tier + messages + temperature. A hit
  is a *previous real response*, recorded with `cached=true`.
* The budget in §5 is enforced before the call, and it fails the scan rather
  than silently truncating it.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .store.models import LLMCall, LLMResponse

TIER_ENV = {
    "fast": "REDFALL_MODEL_FAST",
    "mid": "REDFALL_MODEL_MID",
    "deep": "REDFALL_MODEL_DEEP",
}
TIER_DEFAULTS = {
    "fast": "gpt-4o-mini",
    "mid": "gpt-4o-mini",
    "deep": "gpt-4o",
}

MAX_JSON_REPAIRS = 2


class BudgetExceeded(RuntimeError):
    """The scan hit its token or cost ceiling from §5."""


class LLMError(RuntimeError):
    """The provider call failed, or returned something unusable."""


class JSONParseError(LLMError):
    """The model did not return valid JSON after repair attempts."""

    def __init__(self, content: str, reason: str) -> None:
        self.content = content
        self.reason = reason
        super().__init__(f"model response was not valid JSON ({reason})")


@dataclass
class LLMResult:
    content: str
    model: str
    tier: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    latency_ms: int
    cached: bool
    call_id: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Budget:
    """Running totals against the §5 ceilings.

    Branches run concurrently, so the counters are guarded. A lock around each
    accessor is not enough: `check()` then `add()` is a read-then-write pair, and
    two threads can both pass the check before either records its spend, letting
    the scan exceed the ceiling §5 sets. `record()` does both under one lock for
    callers that spend, which is why it exists beside the plain accessors.
    """

    max_tokens: int
    max_cost_usd: float
    tokens_used: int = 0
    cost_usd: float = 0.0
    calls: int = 0
    cost_unknown_calls: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def add(self, prompt_tokens: int, completion_tokens: int, cost_usd: float | None) -> None:
        with self._lock:
            self.tokens_used += prompt_tokens + completion_tokens
            self.calls += 1
            if cost_usd is None:
                self.cost_unknown_calls += 1
            else:
                self.cost_usd += cost_usd

    def remaining_tokens(self) -> int:
        with self._lock:
            return max(0, self.max_tokens - self.tokens_used)

    def check(self) -> None:
        with self._lock:
            self._check_locked()

    def _check_locked(self) -> None:
        if self.tokens_used > self.max_tokens:
            raise BudgetExceeded(
                f"token budget exhausted: {self.tokens_used} used of {self.max_tokens} permitted"
            )
        if self.cost_usd > self.max_cost_usd:
            raise BudgetExceeded(
                f"cost ceiling exceeded: ${self.cost_usd:.2f} used of ${self.max_cost_usd:.2f} permitted"
            )

    def record(
        self, prompt_tokens: int, completion_tokens: int, cost_usd: float | None
    ) -> None:
        """Add a call's spend and check the ceiling as one atomic step.

        This is what a caller that has just spent should use. It keeps the
        check-then-add pair indivisible, so concurrent branches cannot each
        observe headroom that only one of them has.
        """
        with self._lock:
            self.tokens_used += prompt_tokens + completion_tokens
            self.calls += 1
            if cost_usd is None:
                self.cost_unknown_calls += 1
            else:
                self.cost_usd += cost_usd
            self._check_locked()

    def snapshot(self) -> dict[str, Any]:
        """Counters read together, so a report cannot show a torn total."""
        with self._lock:
            return {
                "tokens_used": self.tokens_used,
                "cost_usd": round(self.cost_usd, 4),
                "calls": self.calls,
                "cost_unknown_calls": self.cost_unknown_calls,
            }

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.snapshot(),
            "max_tokens": self.max_tokens,
            "max_cost_usd": self.max_cost_usd,
        }


def model_for_tier(tier: str) -> str:
    """Resolve the model id for a tier, honouring the REDFALL_MODEL_* overrides."""
    import os

    if tier not in TIER_DEFAULTS:
        raise ValueError(f"unknown model tier {tier!r}; expected one of {sorted(TIER_DEFAULTS)}")
    return os.getenv(TIER_ENV[tier]) or TIER_DEFAULTS[tier]


def request_hash(model: str, tier: str, messages: list[dict[str, str]], temperature: float) -> str:
    payload = json.dumps(
        {"model": model, "tier": tier, "temperature": temperature, "messages": messages},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def extract_json(content: str) -> Any:
    """Parse the first complete JSON value out of a model response.

    Models wrap JSON in prose and in ``` fences. Rather than reject those, this
    finds the first balanced `{...}` or `[...]` block and parses that. Anything
    genuinely unparseable raises — callers must not invent a default.
    """
    text = content.strip()
    if not text:
        raise JSONParseError(content, "empty response")

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fenced = _strip_fence(text)
    if fenced is not None:
        try:
            return json.loads(fenced)
        except json.JSONDecodeError:
            pass

    for opener, closer in (("{", "}"), ("[", "]")):
        candidate = _first_balanced(text, opener, closer)
        if candidate is not None:
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue

    raise JSONParseError(content, "no balanced JSON object or array found")


def _strip_fence(text: str) -> str | None:
    if not text.startswith("```"):
        return None
    lines = text.splitlines()
    if len(lines) < 2:
        return None
    body = lines[1:]
    if body and body[-1].strip().startswith("```"):
        body = body[:-1]
    return "\n".join(body).strip()


def _first_balanced(text: str, opener: str, closer: str) -> str | None:
    start = text.find(opener)
    if start == -1:
        return None
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


class LLM:
    """The only path from Redfall to a model provider."""

    def __init__(self, session_factory, budget: Budget) -> None:
        self._session_factory = session_factory
        self.budget = budget

    # -- core call ---------------------------------------------------------
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
    ) -> LLMResult:
        """Make one real provider call, persist it, and return the result."""
        model = model_for_tier(tier)
        digest = request_hash(model, tier, messages, temperature)

        cached = self._lookup(digest)
        if cached is not None:
            self.budget.record(cached.prompt_tokens, cached.completion_tokens, cached.cost_usd)
            return cached

        self.budget.check()

        import litellm

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
            raise LLMError(f"{model} call failed at stage {stage!r}: {type(err).__name__}: {err}") from err
        latency_ms = int((time.time() - started) * 1000)

        raw = _response_to_dict(response)
        content = _response_content(raw)
        usage = raw.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or 0)
        cost = _cost_usd(response)

        call_id = self._record(
            digest=digest,
            scan_id=scan_id,
            branch_id=branch_id,
            stage=stage,
            tier=tier,
            model=model,
            messages=messages,
            temperature=temperature,
            raw=raw,
            content=content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost,
            latency_ms=latency_ms,
            cached=False,
        )

        self.budget.record(prompt_tokens, completion_tokens, cost)

        return LLMResult(
            content=content,
            model=model,
            tier=tier,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost or 0.0,
            latency_ms=latency_ms,
            cached=False,
            call_id=call_id,
            raw=raw,
        )

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
    ) -> tuple[Any, LLMResult]:
        """Complete and parse JSON, re-prompting the model on malformed output.

        The repair attempts are real calls too, and are recorded like any other.
        If the model never produces valid JSON this raises; it never fabricates.
        """
        working = list(messages)
        last: LLMResult | None = None
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
            last = result
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
        raise LLMError("unreachable: JSON repair loop exited without a result") from None

    # -- persistence -------------------------------------------------------
    def _lookup(self, digest: str) -> LLMResult | None:
        with self._session_factory() as session:
            row = session.execute(
                select(LLMResponse).where(LLMResponse.id == digest)
            ).scalar_one_or_none()
            if row is None:
                return None
            call = session.get(LLMCall, row.call_id)
            if call is None:
                return None
            # Reuse requires an intact transcript; otherwise treat as a miss.
            if not row.content:
                return None
            self._record(
                digest=digest,
                scan_id=call.scan_id,
                branch_id=call.branch_id,
                stage=call.stage,
                tier=call.tier,
                model=call.model,
                messages=(row.request_json or {}).get("messages", []),
                temperature=float((row.request_json or {}).get("temperature", 0.2)),
                raw=row.response_json or {},
                content=row.content,
                prompt_tokens=call.prompt_tokens,
                completion_tokens=call.completion_tokens,
                cost_usd=call.cost_usd,
                latency_ms=0,
                cached=True,
                reuse_of=row.id,
            )
            return LLMResult(
                content=row.content,
                model=call.model,
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
        model: str,
        messages: list[dict[str, str]],
        temperature: float,
        raw: dict[str, Any],
        content: str,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: float | None,
        latency_ms: int,
        cached: bool,
        reuse_of: str | None = None,
    ) -> str:
        call_id = hashlib.sha256(f"{digest}:{stage}:{scan_id}:{time.time_ns()}".encode()).hexdigest()[:16]
        with self._session_factory() as session:
            session.add(
                LLMCall(
                    id=call_id,
                    scan_id=scan_id,
                    branch_id=branch_id,
                    stage=stage,
                    tier=tier,
                    model=model,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    cost_usd=cost_usd if cost_usd is not None else 0.0,
                    latency_ms=latency_ms,
                    cached=cached,
                    request_hash=digest,
                )
            )
            # A cache hit reuses the stored transcript verbatim; only a fresh
            # provider call writes a new one.
            if reuse_of is None:
                session.add(
                    LLMResponse(
                        id=digest,
                        call_id=call_id,
                        request_json={
                            "model": model,
                            "tier": tier,
                            "temperature": temperature,
                            "messages": messages,
                        },
                        response_json=raw,
                        content=content,
                    )
                )
        return call_id


def _response_to_dict(response: Any) -> dict[str, Any]:
    """Normalise a LiteLLM response object into plain JSON-able data."""
    dumped = None
    if hasattr(response, "model_dump"):
        try:
            dumped = response.model_dump()
        except Exception as err:  # noqa: BLE001 - fall through to manual shaping
            dumped = None
            _dump_error = f"{type(err).__name__}: {err}"
        else:
            _dump_error = ""
    if isinstance(dumped, dict):
        if _dump_error:
            dumped["_model_dump_error"] = _dump_error
        return dumped
    if isinstance(response, dict):
        return response
    out: dict[str, Any] = {"raw_type": type(response).__name__}
    for attr in ("id", "model", "usage"):
        if hasattr(response, attr):
            out[attr] = getattr(response, attr)
    # Normalise choices into the dict shape `_response_content` reads, so an
    # object-style response does not silently lose its text.
    shaped: list[dict[str, Any]] = []
    for choice in getattr(response, "choices", None) or []:
        message = getattr(choice, "message", None)
        shaped.append({"message": {"content": getattr(message, "content", "") or ""}})
    out["choices"] = shaped
    return json.loads(json.dumps(out, default=str))


def _response_content(raw: dict[str, Any]) -> str:
    choices = raw.get("choices") or []
    if not choices:
        return ""
    first = choices[0]
    if isinstance(first, dict):
        message = first.get("message") or {}
        if isinstance(message, dict):
            return str(message.get("content") or "")
    message = getattr(first, "message", None)
    return str(getattr(message, "content", "") or "")


def _cost_usd(response: Any) -> float | None:
    """Provider-reported or LiteLLM-computed cost. None when it cannot be known."""
    import litellm

    try:
        value = litellm.completion_cost(completion_response=response)
    except Exception:  # noqa: BLE001 - unknown model pricing is not a scan failure
        return None
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def new_budget(max_tokens: int, max_cost_usd: float) -> Budget:
    return Budget(max_tokens=max_tokens, max_cost_usd=max_cost_usd)


def make_llm(session_factory, budget: Budget) -> LLM:
    return LLM(session_factory=session_factory, budget=budget)
