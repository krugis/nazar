from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from nazar.core.clock import FrozenClock
from nazar.models import Action, ApprovalStatus, Decision, Event, Outcome, Verdict
from nazar.store import Store, VerdictRecord
from nazar.store.migrations import MIGRATIONS


def _event(clock: FrozenClock, alert_id: int = 1, scenario: str = "crowdsecurity/ssh-bf") -> Event:
    return Event(
        alert_id=alert_id,
        source_ip="203.0.113.45",
        scenario=scenario,
        started_at=clock.now(),
        stopped_at=clock.now(),
        event_count=5,
        sample_lines=["user=root service=ssh"],
    )


def _decision(outcome: Outcome = Outcome.AUTO, action: Action = Action.BAN) -> Decision:
    return Decision(action=action, outcome=outcome, intended_outcome=outcome, duration="4h")


def _seed(store: Store, clock: FrozenClock) -> tuple[str, int]:
    inc = store.incidents.create("203.0.113.45", clock.now())
    vid = store.verdicts.add(inc.id, VerdictRecord(Verdict.unknown("x"), "m", "triage-v1"))
    return inc.id, vid


def test_migrations_apply_and_reopen(tmp_path: Path, clock: FrozenClock) -> None:
    s = Store(tmp_path / "a.db", clock)
    assert s.db.schema_version == MIGRATIONS[-1][0]
    s.close()
    s2 = Store(tmp_path / "a.db", clock)
    assert s2.db.schema_version == MIGRATIONS[-1][0]
    s2.close()
    assert oct((tmp_path / "a.db").stat().st_mode & 0o777) == "0o640"


def test_incident_ids_sequence(store: Store, clock: FrozenClock) -> None:
    a = store.incidents.create("203.0.113.1", clock.now())
    b = store.incidents.create("203.0.113.2", clock.now())
    assert a.id == "inc_2026_10_25_0001"
    assert b.id == "inc_2026_10_25_0002"
    clock.advance(days=1)
    assert store.incidents.create("203.0.113.3", clock.now()).id == "inc_2026_10_26_0001"


def test_find_open_respects_window(store: Store, clock: FrozenClock) -> None:
    inc = store.incidents.create("203.0.113.45", clock.now())
    assert store.incidents.find_open("203.0.113.45", clock.now() - timedelta(minutes=30))
    clock.advance(minutes=31)
    assert store.incidents.find_open("203.0.113.45", clock.now() - timedelta(minutes=30)) is None
    assert store.incidents.close_stale(clock.now() - timedelta(minutes=30)) == 1
    row = store.incidents.get(inc.id)
    assert row is not None and row.status.value == "closed"


def test_event_merge_and_seen(store: Store, clock: FrozenClock) -> None:
    inc = store.incidents.create("203.0.113.45", clock.now())
    row = store.events.add(inc.id, _event(clock), max_lines=2)
    merged = store.events.merge(row, _event(clock, alert_id=2), max_lines=2)
    assert merged.event_count == 10 and merged.merged_alerts == 2
    assert len(merged.sample_lines) == 2
    assert store.events.for_incident(inc.id)[0].event_count == 10
    store.events.mark_seen(1)
    store.events.mark_seen(1)
    assert store.events.is_seen(1) and not store.events.is_seen(99)


def test_transaction_rolls_back(store: Store, clock: FrozenClock) -> None:
    with pytest.raises(RuntimeError), store.transaction():
        store.incidents.create("203.0.113.45", clock.now())
        raise RuntimeError
    assert store.incidents.pending_triage() == []


def test_audit_log_is_append_only(store: Store) -> None:
    store.audit.append("system", "health", {"lapi": "up"})
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        store.db.execute("UPDATE audit_log SET actor = 'x'")


def test_decision_lifecycle(store: Store, clock: FrozenClock) -> None:
    inc_id, vid = _seed(store, clock)
    did = store.decisions.add(inc_id, vid, _decision(), idempotency_key="k1")
    assert store.decisions.by_idempotency_key("k1").id == did  # type: ignore[union-attr]
    assert [d.id for d in store.decisions.unapplied_auto()] == [did]
    store.decisions.mark_applied(did, "123")
    assert store.decisions.count_auto_enforced(clock.now() - timedelta(hours=1)) == 1
    applied = store.decisions.applied(incident_id=inc_id)
    assert applied[0].source_ip == "203.0.113.45" and applied[0].crowdsec_alert_id == "123"
    store.decisions.mark_rolled_back(did, "user:cli:root")
    assert store.decisions.applied(incident_id=inc_id) == []
    with pytest.raises(sqlite3.IntegrityError):
        store.decisions.add(inc_id, vid, _decision(), idempotency_key="k1")


def test_approval_single_shot_and_expiry(store: Store, clock: FrozenClock) -> None:
    inc_id, vid = _seed(store, clock)
    a1 = store.approvals.create(
        store.decisions.add(inc_id, vid, _decision(Outcome.APPROVAL)), timedelta(minutes=60)
    )
    assert len(a1.approval_id) == 11 and a1.incident_id == inc_id
    assert store.approvals.resolve(a1.approval_id, ApprovalStatus.APPROVED, "user:1")
    assert not store.approvals.resolve(a1.approval_id, ApprovalStatus.REJECTED, "user:2")
    a2 = store.approvals.create(
        store.decisions.add(inc_id, vid, _decision(Outcome.APPROVAL)), timedelta(minutes=60)
    )
    clock.advance(minutes=61)
    expired = store.approvals.expire_due()
    assert [a.approval_id for a in expired] == [a2.approval_id]
    assert store.approvals.get(a2.approval_id).status is ApprovalStatus.EXPIRED  # type: ignore[union-attr]


def test_kv_and_cti_cache(store: Store, clock: FrozenClock) -> None:
    store.kv.set("lapi.cursor", 42)
    store.kv.set("lapi.cursor", 43)
    assert store.kv.get("lapi.cursor") == 43
    assert store.kv.get("missing", 0) == 0
    store.cti_cache.put("203.0.113.45", {"reputation": "malicious"})
    assert store.cti_cache.get("203.0.113.45", timedelta(hours=24)) == {"reputation": "malicious"}
    clock.advance(hours=25)
    assert store.cti_cache.get("203.0.113.45", timedelta(hours=24)) is None


def test_purge_keeps_active_bans(store: Store, clock: FrozenClock) -> None:
    old_id, _ = _seed(store, clock)
    keep = store.incidents.create("203.0.113.46", clock.now())
    keep_vid = store.verdicts.add(keep.id, VerdictRecord(Verdict.unknown("x"), "m", "v"))
    clock.advance(days=91)
    did = store.decisions.add(keep.id, keep_vid, _decision())
    store.decisions.mark_applied(did, "9")
    store.incidents.close_stale(clock.now())
    removed = store.purge(timedelta(days=90), timedelta(hours=24), timedelta(hours=24))
    assert removed == 1
    assert store.incidents.get(old_id) is None
    assert store.incidents.get(keep.id) is not None


def test_approval_ids_are_cli_safe() -> None:
    from nazar.store.triage import new_approval_id

    ids = {new_approval_id() for _ in range(2000)}
    assert len(ids) == 2000
    assert all(len(i) == 11 and i.isalnum() for i in ids)
