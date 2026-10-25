"""Health state tracking: notify on changes, repeat while down (LLD 11)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from nazar.core.clock import Clock
from nazar.core.log import get_logger
from nazar.notify.base import Notifier
from nazar.notify.messages import HealthNote

log = get_logger(__name__)

State = Literal["up", "down", "warning"]
REPEAT_EVERY = timedelta(minutes=15)


@dataclass
class _Entry:
    state: State
    detail: str
    sent_at: datetime | None


class HealthMonitor:
    def __init__(self, clock: Clock, notifier: Notifier) -> None:
        self._clock = clock
        self._notifier = notifier
        self._state: dict[str, _Entry] = {}

    def snapshot(self) -> dict[str, str]:
        return {k: v.state for k, v in self._state.items()}

    async def update(self, component: str, state: State, detail: str = "") -> None:
        """Record a component's state. Sends a notification when it changes; a component that
        stays down (or keeps warning) is re-notified every 15 minutes. A healthy first
        observation is silent."""
        now = self._clock.now()
        prev = self._state.get(component)
        changed = prev is None or prev.state != state
        due = (
            prev is not None
            and state != "up"
            and (prev.sent_at is None or now - prev.sent_at >= REPEAT_EVERY)
        )
        send = (changed and not (prev is None and state == "up")) or (not changed and due)
        entry = _Entry(state, detail, prev.sent_at if prev else None)
        if send:
            await self._notifier.send(HealthNote(component=component, state=state, detail=detail))
            entry.sent_at = now
            log.info("health_changed", component=component, state=state, detail=detail)
        self._state[component] = entry
