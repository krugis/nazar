from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from nazar.analyst import BackendHealth, ChatResult
from nazar.core.errors import LlmError
from nazar.models import Incident


class FakeBackend:
    """Returns queued outputs; an Exception in the queue is raised."""

    model = "fake-model"

    def __init__(self, *outputs: str | Exception) -> None:
        self.outputs = list(outputs)
        self.calls: list[list[dict[str, str]]] = []

    async def chat(self, messages: list[dict[str, str]], schema: dict[str, Any]) -> ChatResult:
        self.calls.append(messages)
        out = self.outputs.pop(0)
        if isinstance(out, Exception):
            raise out
        return ChatResult(out, 10, self.model)

    async def health(self) -> BackendHealth:
        return BackendHealth(True, True)


@pytest.fixture
def incident() -> Incident:
    ts = datetime(2026, 10, 25, 17, 2, 11, tzinfo=UTC)
    return Incident(
        incident_id="inc_2026_10_25_0001",
        source_ip="203.0.113.45",
        first_seen=ts,
        last_seen=ts,
        scenarios=["crowdsecurity/ssh-bf"],
        event_count=6,
        sample_lines=["service=ssh target_user=root"],
        host_context={"exposed_services": ["ssh"]},
    )


__all__ = ["FakeBackend", "LlmError"]
