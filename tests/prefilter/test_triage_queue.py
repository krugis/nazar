from __future__ import annotations

import asyncio
from datetime import timedelta

from nazar.core.clock import FrozenClock
from nazar.models import IncidentStatus
from nazar.prefilter import TriageQueue
from nazar.store import IncidentRow


def _inc(
    clock: FrozenClock, iid: str, scenarios: int = 1, events: int = 1, age_s: int = 0
) -> IncidentRow:
    ts = clock.now() - timedelta(seconds=age_s)
    return IncidentRow(
        iid,
        "203.0.113.1",
        IncidentStatus.OPEN,
        ts,
        ts,
        events,
        [f"s{i}" for i in range(scenarios)],
        True,
        None,
        ts,
        ts,
    )


def test_priority_order(clock: FrozenClock) -> None:
    q = TriageQueue(clock, 10, 100)
    q.push(_inc(clock, "a"))
    q.push(_inc(clock, "b", scenarios=2))
    q.push(_inc(clock, "c"), banned=True)
    q.push(_inc(clock, "d", age_s=60))  # same priority as a, older
    assert [q.pop_nowait() for _ in range(4)] == ["b", "d", "a", "c"]
    assert q.pop_nowait() is None


def test_overflow_evicts_lowest_oldest(clock: FrozenClock) -> None:
    q = TriageQueue(clock, 10, 2)
    assert q.push(_inc(clock, "a", scenarios=3)) == []
    assert q.push(_inc(clock, "b", age_s=10)) == []
    assert q.push(_inc(clock, "c")) == ["b"]
    assert len(q) == 2 and "b" not in q


async def test_rate_limit(clock: FrozenClock) -> None:
    q = TriageQueue(clock, 2, 100)  # 2 per minute, burst of 2
    for i in range(3):
        q.push(_inc(clock, f"i{i}", age_s=i))
    start = clock.now()
    await q.next()
    await q.next()
    assert clock.now() == start
    await q.next()
    assert (clock.now() - start).total_seconds() >= 29.9


async def test_next_waits_for_items(clock: FrozenClock) -> None:
    q = TriageQueue(clock, 10, 100)
    task = asyncio.create_task(q.next())
    await asyncio.sleep(0)
    assert not task.done()
    q.push(_inc(clock, "x"))
    assert await asyncio.wait_for(task, 1) == "x"
