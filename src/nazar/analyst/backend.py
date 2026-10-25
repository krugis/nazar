"""LLM backend interface (LLD 07)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class ChatResult:
    content: str
    latency_ms: int
    model: str


@dataclass(frozen=True)
class BackendHealth:
    reachable: bool
    model_present: bool
    version: str | None = None
    detail: str | None = None


class LlmBackend(Protocol):
    model: str

    async def chat(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> ChatResult:
        """Raises ``LlmError`` when the backend fails or times out."""
        ...

    async def health(self) -> BackendHealth: ...
