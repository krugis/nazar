"""Ollama ``/api/chat`` backend (LLD 07, verified against ollama/docs/api.md)."""

from __future__ import annotations

import time
from typing import Any

import httpx

from nazar.analyst.backend import BackendHealth, ChatResult
from nazar.config import AnalystConfig
from nazar.core.errors import LlmError


def _same_model(name: str, wanted: str) -> bool:
    def norm(n: str) -> str:
        return n.removesuffix(":latest").lower()

    return norm(name) == norm(wanted)


class OllamaBackend:
    def __init__(self, cfg: AnalystConfig, http: httpx.AsyncClient) -> None:
        self.model = cfg.model
        self._cfg = cfg
        self._http = http

    def _payload(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self._cfg.model,
            "messages": messages,
            "stream": False,
            "format": schema,
            "options": {
                "temperature": self._cfg.temperature,
                "num_ctx": self._cfg.num_ctx,
                "num_predict": self._cfg.num_predict,
            },
            "keep_alive": self._cfg.keep_alive,
        }
        if self._cfg.think is not None:
            payload["think"] = self._cfg.think
        return payload

    async def chat(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> ChatResult:
        start = time.monotonic()
        try:
            resp = await self._http.post(
                "/api/chat",
                json=self._payload(messages, schema),
                timeout=self._cfg.timeout_seconds,
            )
        except httpx.TimeoutException as exc:
            raise LlmError(f"Ollama timed out after {self._cfg.timeout_seconds:g}s") from exc
        except httpx.HTTPError as exc:
            raise LlmError(f"Ollama request failed: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise LlmError(f"Ollama returned HTTP {resp.status_code}")
        try:
            data = resp.json()
            message = data["message"]
            content = message.get("content") or ""
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise LlmError("Ollama returned an unexpected response") from exc
        # message["thinking"] is deliberately ignored: reasoning text is never the answer.
        return ChatResult(
            content=str(content),
            latency_ms=int((time.monotonic() - start) * 1000),
            model=str(data.get("model") or self._cfg.model),
        )

    async def health(self) -> BackendHealth:
        try:
            version = (await self._http.get("/api/version", timeout=5)).json().get("version")
            tags = (await self._http.get("/api/tags", timeout=5)).json().get("models") or []
        except (httpx.HTTPError, ValueError, AttributeError) as exc:
            return BackendHealth(False, False, detail=type(exc).__name__)
        names = [str(m.get("name") or m.get("model") or "") for m in tags if isinstance(m, dict)]
        present = any(_same_model(n, self._cfg.model) for n in names)
        return BackendHealth(True, present, version=version)
