from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import timedelta
from typing import Any

from nazar.core.clock import FrozenClock
from nazar.enrich import AlertGeoProvider, Enricher, HistoryProvider
from nazar.models import Action, Decision, Event, Incident, Outcome, Verdict
from nazar.store import EventRow, Store, VerdictRecord


class _Static:
    def __init__(self, name: str, data: dict[str, Any]) -> None:
        self.name = name
        self.data = data

    async def enrich(self, incident: Incident, events: Sequence[EventRow]) -> dict[str, Any]:
        return self.data


class _Broken:
    name = "broken"

    async def enrich(self, incident: Incident, events: Sequence[EventRow]) -> dict[str, Any]:
        raise RuntimeError("boom")


class _Slow:
    name = "slow"

    async def enrich(self, incident: Incident, events: Sequence[EventRow]) -> dict[str, Any]:
        await asyncio.sleep(5)
        return {"country": "ZZ"}


def _incident(clock: FrozenClock, iid: str = "inc_x") -> Incident:
    return Incident(
        incident_id=iid,
        source_ip="203.0.113.45",
        first_seen=clock.now(),
        last_seen=clock.now(),
        scenarios=["s"],
        event_count=1,
    )


async def test_merge_precedence_and_failures(clock: FrozenClock) -> None:
    enricher = Enricher(
        [
            _Static("a", {"country": "XX", "cti_behaviors": ["ssh:bruteforce"]}),
            _Broken(),
            _Slow(),
            _Static(
                "b",
                {
                    "country": "YY",
                    "asn": "AS1 X",
                    "cti_behaviors": ["ssh:bruteforce", "http:scan"],
                    "unknown_key": 1,
                },
            ),
        ],
        timeout_s=0.05,
    )
    e = await enricher.enrich(_incident(clock), [])
    assert e.country == "XX" and e.asn == "AS1 X"
    assert e.cti_behaviors == ["ssh:bruteforce", "http:scan"]
    assert e.cti_reputation is None


async def test_alert_geo_and_history(store: Store, clock: FrozenClock) -> None:
    old = store.incidents.create("203.0.113.45", clock.now() - timedelta(days=2))
    store.events.add(
        old.id,
        Event(
            alert_id=1,
            source_ip="203.0.113.45",
            scenario="s",
            started_at=clock.now(),
            stopped_at=clock.now(),
            crowdsec_decisions=["ban"],
        ),
        5,
    )
    vid = store.verdicts.add(old.id, VerdictRecord(Verdict.unknown("x"), "m", "v"))
    did = store.decisions.add(
        old.id,
        vid,
        Decision(action=Action.BAN, outcome=Outcome.AUTO, intended_outcome=Outcome.AUTO),
    )
    store.decisions.mark_applied(did, "1")
    cur = store.incidents.create("203.0.113.45", clock.now())
    row = store.events.add(
        cur.id,
        Event(
            alert_id=2,
            source_ip="203.0.113.45",
            scenario="s",
            started_at=clock.now(),
            stopped_at=clock.now(),
            country="XX",
            asn="AS64500 Example",
        ),
        5,
    )
    enricher = Enricher([AlertGeoProvider(), HistoryProvider(store)])
    e = await enricher.enrich(_incident(clock, cur.id), [row])
    assert (e.country, e.asn) == ("XX", "AS64500 Example")
    assert e.history.previous_incidents == 1
    assert e.history.previous_bans == 2  # one Nazar ban + one CrowdSec ban
