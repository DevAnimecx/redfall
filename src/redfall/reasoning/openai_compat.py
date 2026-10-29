"""Any OpenAI-compatible endpoint (0.2.7).

This covers the whole "bring your own endpoint" field with one backend: Ollama,
vLLM, LM Studio, llama.cpp server, OpenRouter, a corporate gateway, or a local
agent that exposes the OpenAI chat shape. There is no per-vendor code, because
they all speak the same request.

The key is read from a named env var and never stored. When the endpoint needs
no key (a local Ollama) the backend is still honest about sending nothing.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from ..llm import model_for_tier
from .backend import BackendError, BackendResult, ReasoningBackend

DEFAULT_BASE_URL = "http://localhost:11434/v1"
DEFAULT_MODEL = "qwen2.5-coder:32b"


class OpenAICompatBackend(ReasoningBackend):
    name = "openai_compat"

    def __init__(
        self,
        *,
        base_url: str | None,
        model: str | None,
        api_key_env: str | None,
        session_factory,
        budget,
        timeout_s: int = 300,
    ) -> None:
        super().__init__(budget=budget)
        self._base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self._model = model or DEFAULT_MODEL
        self._api_key_env = api_key_env
        self._session_factory = session_factory
        self._timeout_s = timeout_s

    def model_for_tier(self, tier: str) -> str:
        """One endpoint usually serves one model; the tier is a fallback only.

        When the operator named a model, every tier uses it. When they did not,
        the tier falls back to the LiteLLM tier default so a `deep` stage is not
        silently served by the same small model.
        """
        if self._model != DEFAULT_MODEL:
            return self._model
        try:
            return model_for_tier(tier)
        except ValueError:
            return self._model

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": "openai_compat",
            "base_url": self._base_url,
            "model": self._model,
            "key_env": self._api_key_env,
            "key_present": self._key() is not None,
        }

    def available(self) -> bool:
        # A local endpoint needs no key; we only require that the URL is set,
        # which it always is (it has a default). Reachability is proven on call.
        return True

    def _key(self) -> str | None:
        import os

        env = self._api_key_env or "OPENAI_API_KEY"
        return os.getenv(env)

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
        model = self.model_for_tier(tier)
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            body["max_tokens"] = max_tokens

        headers = {"Content-Type": "application/json"}
        key = self._key()
        if key:
            headers["Authorization"] = f"Bearer {key}"

        request = urllib.request.Request(
            f"{self._base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        started = time.time()
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_s) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            detail = err.read().decode("utf-8", "replace")[:400]
            raise BackendError(
                f"{self._base_url} returned HTTP {err.code} at stage {stage!r}: {detail}"
            ) from err
        except (urllib.error.URLError, OSError) as err:
            raise BackendError(
                f"cannot reach {self._base_url} at stage {stage!r}: {err}. "
                "Check the endpoint is running and `base_url` in redfall.toml is right."
            ) from err
        except json.JSONDecodeError as err:
            raise BackendError(
                f"{self._base_url} returned a non-JSON body at stage {stage!r}"
            ) from err

        latency_ms = int((time.time() - started) * 1000)
        return BackendResult(
            content=_content(payload),
            model=model,
            backend=self.name,
            tier=tier,
            prompt_tokens=int((payload.get("usage") or {}).get("prompt_tokens") or 0),
            completion_tokens=int((payload.get("usage") or {}).get("completion_tokens") or 0),
            cost_usd=0.0,
            latency_ms=latency_ms,
            cached=False,
            raw=payload,
        )


def _content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices") or []
    if not choices:
        return ""
    first = choices[0] or {}
    message = first.get("message") or {}
    return str(message.get("content") or "")


__all__ = ["OpenAICompatBackend", "DEFAULT_BASE_URL", "DEFAULT_MODEL"]
