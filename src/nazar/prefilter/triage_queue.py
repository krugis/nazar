"""Priority queue with a token-bucket rate limit in front of the analyst (LLD 05)."""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from datetime import datetime

from nazar.core.clock import Clock
from nazar.store import IncidentRow


@dataclass(frozen=True)
class _Entry:
    incident_id: str
    priority: float
    first_seen: datetime


def priority(inc: IncidentRow, banned: bool) -> float:
    return len(set(inc.scenarios)) * 10 + math.log2(inc.event_count + 1) + (0 if banned else 5)


class TriageQueue:
    """Highest priority first, ties broken by oldest ``first_seen``.

    ``push`` returns the IDs evicted when the queue exceeds ``max_size``: the lowest-priority,
    oldest entries. The caller records them as bulk-summarized.
    """

    def __init__(self, clock: Clock, calls_per_minute: int, max_size: int) -> None:
        self._clock = clock
        self._rate = calls_per_minute / 60.0
        self._capacity = float(calls_per_minute)
        self._tokens = self._capacity
        self._stamp = clock.now()
        self._max = max_size
        self._items: dict[str, _Entry] = {}
        self._ready = asyncio.Event()

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, incident_id: object) -> bool:
        return incident_id in self._items

    def push(self, inc: IncidentRow, banned: bool = False) -> list[str]:
        self._items[inc.id] = _Entry(inc.id, priority(inc, banned), inc.first_seen)
        self._ready.set()
        evicted: list[str] = []
        while len(self._items) > self._max:
            worst = min(self._items.values(), key=lambda e: (e.priority, e.first_seen))
            del self._items[worst.incident_id]
            evicted.append(worst.incident_id)
        return evicted

    def pop_nowait(self) -> str | None:
        if not self._items:
            return None
        best = max(self._items.values(), key=lambda e: (e.priority, -e.first_seen.timestamp()))
        del self._items[best.incident_id]
        if not self._items:
            self._ready.clear()
        return best.incident_id

    def _refill(self) -> None:
        now = self._clock.now()
        elapsed = max((now - self._stamp).total_seconds(), 0.0)
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._stamp = now

    async def next(self) -> str:
        """Wait for an item and a rate-limit token, then return the best incident ID."""
        while True:
            if not self._items:
                await self._ready.wait()
                continue
            self._refill()
            if self._tokens >= 1.0:
                incident_id = self.pop_nowait()
                if incident_id is not None:
                    self._tokens -= 1.0
                    return incident_id
                continue
            await self._clock.sleep((1.0 - self._tokens) / self._rate)
