from __future__ import annotations

from datetime import timedelta

from nazar.config import PolicyConfig, PrefilterConfig
from nazar.core.clock import FrozenClock
from nazar.models import Event
from nazar.prefilter import Grouper, build_allowlist
from nazar.store import Store

IP = "203.0.113.45"


def _ev(
    clock: FrozenClock,
    alert_id: int,
    scenario: str = "crowdsecurity/ssh-bf",
    ip: str = IP,
    banned: bool = False,
    offset_s: float = 0,
) -> Event:
    ts = clock.now() + timedelta(seconds=offset_s)
    return Event(
        alert_id=alert_id,
        source_ip=ip,
        scenario=scenario,
        started_at=ts,
        stopped_at=ts,
        event_count=5,
        sample_lines=[f"line {alert_id}"],
        crowdsec_decisions=["ban"] if banned else [],
    )


def _grouper(store: Store, **cfg: int) -> Grouper:
    allow = build_allowlist(PolicyConfig(allowlist_cidrs=["198.51.100.0/24"]), host_addresses=[])
    return Grouper(store, allow, PrefilterConfig(**cfg))


def test_groups_same_ip_into_one_incident(store: Store, clock: FrozenClock) -> None:
    g = _grouper(store)
    res = g.ingest([_ev(clock, 1), _ev(clock, 2, "crowdsecurity/http-probing", offset_s=60)])
    assert res.new_incidents == 1 and len(res.needs_triage) == 1
    inc = store.incidents.get(res.needs_triage[0])
    assert inc is not None
    assert inc.scenarios == ["crowdsecurity/ssh-bf", "crowdsecurity/http-probing"]
    assert inc.event_count == 10
    assert len(store.events.for_incident(inc.id)) == 2


def test_window_edge_creates_new_incident(store: Store, clock: FrozenClock) -> None:
    g = _grouper(store, incident_window_minutes=30)
    first = g.ingest([_ev(clock, 1)]).needs_triage[0]
    second = g.ingest([_ev(clock, 2, offset_s=31 * 60)]).needs_triage[0]
    assert first != second
    third = g.ingest([_ev(clock, 3, offset_s=40 * 60)]).needs_triage[0]
    assert third == second


def test_dedupe_inside_window(store: Store, clock: FrozenClock) -> None:
    g = _grouper(store, dedupe_window_seconds=300)
    res = g.ingest([_ev(clock, 1), _ev(clock, 2, offset_s=120), _ev(clock, 3, offset_s=500)])
    assert res.merged_alerts == 1
    rows = store.events.for_incident(res.needs_triage[0])
    assert [r.merged_alerts for r in rows] == [2, 1]


def test_needs_triage_rules(store: Store, clock: FrozenClock) -> None:
    g = _grouper(store)
    inc_id = g.ingest([_ev(clock, 1, banned=True)]).needs_triage[0]
    store.incidents.mark_triaged(inc_id, ["crowdsecurity/ssh-bf"])
    # merged duplicate: no new signal
    assert g.ingest([_ev(clock, 2, banned=True, offset_s=10)]).needs_triage == []
    # new non-merged event while CrowdSec already bans: no new signal
    assert g.ingest([_ev(clock, 3, banned=True, offset_s=400)]).needs_triage == []
    # new non-merged event without a ban: new signal
    assert g.ingest([_ev(clock, 4, offset_s=800)]).needs_triage == [inc_id]
    store.incidents.mark_triaged(inc_id, ["crowdsecurity/ssh-bf"])
    # new scenario: new signal even when banned
    res = g.ingest([_ev(clock, 5, "crowdsecurity/http-probing", banned=True, offset_s=900)])
    assert res.needs_triage == [inc_id]


def test_allowlisted_recorded_not_triaged(store: Store, clock: FrozenClock) -> None:
    g = _grouper(store)
    res = g.ingest([_ev(clock, 1, ip="198.51.100.9"), _ev(clock, 2, ip="198.51.100.9")])
    assert res.needs_triage == [] and res.allowlisted == 2
    incs = store.incidents.list(clock.now() - timedelta(hours=1))
    assert len(incs) == 1 and not incs[0].needs_triage
    verdicts = store.verdicts.for_incident(incs[0].id)
    assert len(verdicts) == 1 and verdicts[0].record.skipped_reason == "allowlisted:config"
