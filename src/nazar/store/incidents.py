"""Incident and event repositories (LLD 03)."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from nazar.core.clock import Clock, from_iso, to_iso
from nazar.models import Event, IncidentStatus
from nazar.store.db import Database, dumps, loads


@dataclass
class IncidentRow:
    id: str
    source_ip: str
    status: IncidentStatus
    first_seen: datetime
    last_seen: datetime
    event_count: int
    scenarios: list[str]
    needs_triage: bool
    last_triaged_scenarios: list[str] | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> IncidentRow:
        return cls(
            id=row["id"],
            source_ip=row["source_ip"],
            status=IncidentStatus(row["status"]),
            first_seen=from_iso(row["first_seen"]),
            last_seen=from_iso(row["last_seen"]),
            event_count=row["event_count"],
            scenarios=loads(row["scenarios"]),
            needs_triage=bool(row["needs_triage"]),
            last_triaged_scenarios=loads(row["last_triaged_scenarios"]),
            created_at=from_iso(row["created_at"]),
            updated_at=from_iso(row["updated_at"]),
        )


class IncidentRepo:
    def __init__(self, db: Database, clock: Clock) -> None:
        self._db = db
        self._clock = clock

    def next_id(self, day: date) -> str:
        prefix = f"inc_{day:%Y_%m_%d}_"
        row = self._db.one("SELECT COUNT(*) FROM incidents WHERE id LIKE ?", (prefix + "%",))
        count = int(row[0]) if row else 0
        return f"{prefix}{count + 1:04d}"

    def create(self, source_ip: str, first_seen: datetime) -> IncidentRow:
        now = to_iso(self._clock.now())
        with self._db.transaction():
            incident_id = self.next_id(first_seen.date())
            self._db.execute(
                "INSERT INTO incidents (id, source_ip, status, first_seen, last_seen, event_count,"
                " scenarios, needs_triage, created_at, updated_at)"
                " VALUES (?, ?, 'open', ?, ?, 0, '[]', 1, ?, ?)",
                (incident_id, source_ip, to_iso(first_seen), to_iso(first_seen), now, now),
            )
        row = self.get(incident_id)
        assert row is not None
        return row

    def get(self, incident_id: str) -> IncidentRow | None:
        row = self._db.one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        return IncidentRow.from_row(row) if row else None

    def find_open(self, source_ip: str, since: datetime) -> IncidentRow | None:
        row = self._db.one(
            "SELECT * FROM incidents WHERE source_ip = ? AND status = 'open' AND last_seen >= ?"
            " ORDER BY last_seen DESC LIMIT 1",
            (source_ip, to_iso(since)),
        )
        return IncidentRow.from_row(row) if row else None

    def save(self, inc: IncidentRow) -> None:
        inc.updated_at = self._clock.now()
        self._db.execute(
            "UPDATE incidents SET status = ?, first_seen = ?, last_seen = ?, event_count = ?,"
            " scenarios = ?, needs_triage = ?, last_triaged_scenarios = ?, updated_at = ?"
            " WHERE id = ?",
            (
                inc.status.value,
                to_iso(inc.first_seen),
                to_iso(inc.last_seen),
                inc.event_count,
                dumps(inc.scenarios),
                int(inc.needs_triage),
                None if inc.last_triaged_scenarios is None else dumps(inc.last_triaged_scenarios),
                to_iso(inc.updated_at),
                inc.id,
            ),
        )

    def mark_triaged(self, incident_id: str, scenarios: list[str]) -> None:
        self._db.execute(
            "UPDATE incidents SET needs_triage = 0, last_triaged_scenarios = ?, updated_at = ?"
            " WHERE id = ?",
            (dumps(scenarios), to_iso(self._clock.now()), incident_id),
        )

    def pending_triage(self, limit: int = 1000) -> list[IncidentRow]:
        rows = self._db.all(
            "SELECT * FROM incidents WHERE needs_triage = 1 ORDER BY first_seen LIMIT ?", (limit,)
        )
        return [IncidentRow.from_row(r) for r in rows]

    def list(
        self, since: datetime, source_ip: str | None = None, limit: int = 100
    ) -> list[IncidentRow]:
        sql = "SELECT * FROM incidents WHERE last_seen >= ?"
        params: list[Any] = [to_iso(since)]
        if source_ip:
            sql += " AND source_ip = ?"
            params.append(source_ip)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        return [IncidentRow.from_row(r) for r in self._db.all(sql, params)]

    def count_for_ip(self, source_ip: str, exclude_id: str) -> int:
        row = self._db.one(
            "SELECT COUNT(*) FROM incidents WHERE source_ip = ? AND id != ?",
            (source_ip, exclude_id),
        )
        return int(row[0]) if row else 0

    def close_stale(self, before: datetime) -> int:
        cur = self._db.execute(
            "UPDATE incidents SET status = 'closed', updated_at = ?"
            " WHERE status = 'open' AND last_seen < ?",
            (to_iso(self._clock.now()), to_iso(before)),
        )
        return cur.rowcount


@dataclass
class EventRow:
    id: int
    incident_id: str
    alert_id: int
    scenario: str
    first_ts: datetime
    last_ts: datetime
    event_count: int
    merged_alerts: int
    sample_lines: list[str]
    labels: list[str]
    crowdsec_decisions: list[str]

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> EventRow:
        return cls(
            id=row["id"],
            incident_id=row["incident_id"],
            alert_id=row["alert_id"],
            scenario=row["scenario"],
            first_ts=from_iso(row["first_ts"]),
            last_ts=from_iso(row["last_ts"]),
            event_count=row["event_count"],
            merged_alerts=row["merged_alerts"],
            sample_lines=loads(row["sample_lines"]),
            labels=loads(row["labels"]),
            crowdsec_decisions=loads(row["crowdsec_decisions"]),
        )


class EventRepo:
    def __init__(self, db: Database, clock: Clock) -> None:
        self._db = db
        self._clock = clock

    def add(self, incident_id: str, event: Event, max_lines: int) -> EventRow:
        cur = self._db.execute(
            "INSERT INTO events (incident_id, alert_id, scenario, first_ts, last_ts, event_count,"
            " merged_alerts, sample_lines, labels, crowdsec_decisions)"
            " VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
            (
                incident_id,
                event.alert_id,
                event.scenario,
                to_iso(event.started_at),
                to_iso(event.stopped_at),
                event.event_count,
                dumps(event.sample_lines[:max_lines]),
                dumps(event.labels),
                dumps(event.crowdsec_decisions),
            ),
        )
        row = self._db.one("SELECT * FROM events WHERE id = ?", (cur.lastrowid,))
        assert row is not None
        return EventRow.from_row(row)

    def find_mergeable(self, incident_id: str, scenario: str, since: datetime) -> EventRow | None:
        row = self._db.one(
            "SELECT * FROM events WHERE incident_id = ? AND scenario = ? AND last_ts >= ?"
            " ORDER BY last_ts DESC LIMIT 1",
            (incident_id, scenario, to_iso(since)),
        )
        return EventRow.from_row(row) if row else None

    def merge(self, row: EventRow, event: Event, max_lines: int) -> EventRow:
        row.event_count += event.event_count
        row.merged_alerts += 1
        row.last_ts = max(row.last_ts, event.stopped_at)
        room = max_lines - len(row.sample_lines)
        if room > 0:
            row.sample_lines.extend(event.sample_lines[:room])
        row.crowdsec_decisions = sorted(set(row.crowdsec_decisions) | set(event.crowdsec_decisions))
        row.labels = sorted(set(row.labels) | set(event.labels))
        self._db.execute(
            "UPDATE events SET last_ts = ?, event_count = ?, merged_alerts = ?, sample_lines = ?,"
            " labels = ?, crowdsec_decisions = ? WHERE id = ?",
            (
                to_iso(row.last_ts),
                row.event_count,
                row.merged_alerts,
                dumps(row.sample_lines),
                dumps(row.labels),
                dumps(row.crowdsec_decisions),
                row.id,
            ),
        )
        return row

    def for_incident(self, incident_id: str) -> list[EventRow]:
        rows = self._db.all(
            "SELECT * FROM events WHERE incident_id = ? ORDER BY first_ts, id", (incident_id,)
        )
        return [EventRow.from_row(r) for r in rows]

    def mark_seen(self, alert_id: int) -> None:
        self._db.execute(
            "INSERT OR IGNORE INTO seen_alerts (alert_id, seen_at) VALUES (?, ?)",
            (alert_id, to_iso(self._clock.now())),
        )

    def is_seen(self, alert_id: int) -> bool:
        return self._db.one("SELECT 1 FROM seen_alerts WHERE alert_id = ?", (alert_id,)) is not None
