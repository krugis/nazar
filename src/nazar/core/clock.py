"""Injectable time source (decision D7)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """Current time, timezone-aware UTC."""
        ...

    async def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class FrozenClock:
    """Test clock: time only moves when told to (``advance`` or ``sleep``)."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 10, 25, 17, 0, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float = 0, **kwargs: float) -> None:
        self._now += timedelta(seconds=seconds, **kwargs)

    async def sleep(self, seconds: float) -> None:
        self.advance(seconds)
        await asyncio.sleep(0)


def to_iso(value: datetime) -> str:
    """Format as ISO-8601 UTC with a ``Z`` suffix, second precision."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def from_iso(value: str) -> datetime:
    """Parse ISO-8601 (``Z`` or offset, optional fractional seconds) into aware UTC."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Go may emit nanoseconds; Python accepts at most microseconds.
    if "." in text:
        head, _, rest = text.partition(".")
        digits = "".join(ch for ch in rest if ch.isdigit())
        tz = rest[len(digits) :]
        text = f"{head}.{digits[:6]}{tz}"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
