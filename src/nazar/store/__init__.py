"""SQLite store with migrations and an append-only audit log (LLD 03)."""

from __future__ import annotations

from contextlib import AbstractContextManager
from datetime import timedelta
from pathlib import Path

from nazar.core.clock import Clock, to_iso
from nazar.store.db import Database
from nazar.store.incidents import EventRepo, EventRow, IncidentRepo, IncidentRow
from nazar.store.state import AuditLog, CtiCacheRepo, KvRepo
from nazar.store.triage import (
    ERROR_INVALID_OUTPUT,
    ERROR_MODEL_UNAVAILABLE,
    ApprovalRepo,
    DecisionRepo,
    DecisionRow,
    VerdictRecord,
    VerdictRepo,
    VerdictRow,
)

__all__ = [
    "ERROR_INVALID_OUTPUT",
    "ERROR_MODEL_UNAVAILABLE",
    "Database",
    "DecisionRow",
    "EventRow",
    "IncidentRow",
    "Store",
    "VerdictRecord",
    "VerdictRow",
]


class Store:
    """Facade holding the database and every repository."""

    def __init__(self, path: Path | str, clock: Clock) -> None:
        self.db = Database(path)
        self.clock = clock
        self.incidents = IncidentRepo(self.db, clock)
        self.events = EventRepo(self.db, clock)
        self.verdicts = VerdictRepo(self.db, clock)
        self.decisions = DecisionRepo(self.db, clock)
        self.approvals = ApprovalRepo(self.db, clock)
        self.kv = KvRepo(self.db, clock)
        self.cti_cache = CtiCacheRepo(self.db, clock)
        self.audit = AuditLog(self.db, clock)

    def transaction(self) -> AbstractContextManager[None]:
        return self.db.transaction()

    def purge(self, retention: timedelta, max_ban: timedelta, cti_max_age: timedelta) -> int:
        """Delete data older than ``retention``. Returns the number of incidents removed.

        Incidents with an applied, not rolled back decision that could still be active
        (applied within ``max_ban``) are kept.
        """
        now = self.clock.now()
        cutoff = to_iso(now - retention)
        active_since = to_iso(now - max_ban)
        with self.db.transaction():
            cur = self.db.execute(
                "DELETE FROM incidents WHERE status = 'closed' AND last_seen < ? AND id NOT IN ("
                " SELECT incident_id FROM decisions WHERE applied_at IS NOT NULL"
                " AND rolled_back_at IS NULL AND applied_at >= ?)",
                (cutoff, active_since),
            )
            removed = cur.rowcount
            self.db.execute("DELETE FROM seen_alerts WHERE seen_at < ?", (cutoff,))
            self.db.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
            self.db.execute(
                "DELETE FROM cti_cache WHERE fetched_at < ?", (to_iso(now - cti_max_age),)
            )
        self.db.execute("PRAGMA optimize")
        return removed

    def close(self) -> None:
        self.db.close()
