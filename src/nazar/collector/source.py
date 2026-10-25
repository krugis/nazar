"""Alert sources: polling the LAPI with a persisted cursor (LLD 04)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from nazar.collector.lapi import LapiClient
from nazar.collector.normalize import alert_to_event
from nazar.config import CollectorConfig, PrefilterConfig
from nazar.core.clock import Clock, from_iso, to_iso
from nazar.core.log import get_logger
from nazar.models import Event, format_duration, parse_duration
from nazar.store import Store

log = get_logger(__name__)

CURSOR_KEY = "lapi.cursor"
LAST_POLL_KEY = "lapi.last_poll"


@dataclass(frozen=True)
class PollResult:
    events: list[Event]
    seen_alert_ids: list[int]
    """Every new alert ID, including ignored ones, so they are not fetched again."""
    cursor: int
    polled_at: datetime
    truncated: bool = False
    ignored: int = 0


class AlertSource(Protocol):
    async def poll(self) -> PollResult: ...

    def commit(self, result: PollResult) -> None:
        """Persist the cursor. Called inside the transaction that stores the events."""
        ...


class LapiAlertSource:
    def __init__(
        self,
        lapi: LapiClient,
        store: Store,
        clock: Clock,
        collector: CollectorConfig,
        prefilter: PrefilterConfig,
    ) -> None:
        self._lapi = lapi
        self._store = store
        self._clock = clock
        self._cfg = collector
        self._pf = prefilter

    def _since(self, now: datetime) -> str:
        lookback = parse_duration(self._cfg.lookback)
        raw = self._store.kv.get(LAST_POLL_KEY)
        last_poll = from_iso(raw) if raw else now - lookback
        window = now - last_poll + timedelta(seconds=2 * self._cfg.interval_seconds)
        window = min(max(window, timedelta(seconds=self._cfg.interval_seconds)), lookback * 24)
        return format_duration(timedelta(seconds=int(window.total_seconds())))

    async def poll(self) -> PollResult:
        now = self._clock.now()
        cursor = int(self._store.kv.get(CURSOR_KEY, 0))
        alerts = await self._lapi.get_alerts(since=self._since(now), limit=self._cfg.batch_limit)
        truncated = len(alerts) >= self._cfg.batch_limit
        if truncated:
            log.warning("lapi_batch_truncated", limit=self._cfg.batch_limit)

        fresh = sorted(
            (a for a in alerts if isinstance(a.get("id"), int)),
            key=lambda a: int(a["id"]),
        )
        events: list[Event] = []
        seen: list[int] = []
        ignored = 0
        for alert in fresh:
            alert_id = int(alert["id"])
            # The cursor only moves forward; seen_alerts also catches late, lower IDs.
            if self._store.events.is_seen(alert_id):
                continue
            seen.append(alert_id)
            event = alert_to_event(
                alert,
                now=now,
                max_lines=self._pf.max_sample_lines,
                max_len=self._pf.max_line_length,
            )
            if event is None:
                ignored += 1
            else:
                events.append(event)
        new_cursor = max([cursor, *seen])
        return PollResult(events, seen, new_cursor, now, truncated, ignored)

    def commit(self, result: PollResult) -> None:
        for alert_id in result.seen_alert_ids:
            self._store.events.mark_seen(alert_id)
        self._store.kv.set(CURSOR_KEY, result.cursor)
        self._store.kv.set(LAST_POLL_KEY, to_iso(result.polled_at))
