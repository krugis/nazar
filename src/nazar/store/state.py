"""Small state: key/value, CTI cache and the audit log (LLD 03)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from nazar.core.clock import Clock, to_iso
from nazar.store.db import Database, dumps, loads


class KvRepo:
    def __init__(self, db: Database, clock: Clock) -> None:
        self._db = db
        self._clock = clock

    def get(self, key: str, default: Any = None) -> Any:
        row = self._db.one("SELECT value FROM kv WHERE key = ?", (key,))
        return loads(row["value"]) if row else default

    def set(self, key: str, value: Any) -> None:
        self._db.execute(
            "INSERT INTO kv (key, value, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
            " updated_at = excluded.updated_at",
            (key, dumps(value), to_iso(self._clock.now())),
        )


class CtiCacheRepo:
    def __init__(self, db: Database, clock: Clock) -> None:
        self._db = db
        self._clock = clock

    def get(self, ip: str, max_age: timedelta) -> dict[str, Any] | None:
        row = self._db.one(
            "SELECT body FROM cti_cache WHERE ip = ? AND fetched_at >= ?",
            (ip, to_iso(self._clock.now() - max_age)),
        )
        return loads(row["body"]) if row else None

    def put(self, ip: str, body: dict[str, Any]) -> None:
        self._db.execute(
            "INSERT INTO cti_cache (ip, fetched_at, body) VALUES (?, ?, ?)"
            " ON CONFLICT(ip) DO UPDATE SET fetched_at = excluded.fetched_at, body = excluded.body",
            (ip, to_iso(self._clock.now()), dumps(body)),
        )


class AuditLog:
    """Append-only record of verdicts, decisions, approvals and rollbacks."""

    def __init__(self, db: Database, clock: Clock) -> None:
        self._db = db
        self._clock = clock

    def append(
        self,
        actor: str,
        kind: str,
        detail: dict[str, Any],
        incident_id: str | None = None,
        ref_id: str | int | None = None,
    ) -> None:
        self._db.execute(
            "INSERT INTO audit_log (ts, actor, kind, incident_id, ref_id, detail)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                to_iso(self._clock.now()),
                str(actor),
                kind,
                incident_id,
                None if ref_id is None else str(ref_id),
                dumps(detail),
            ),
        )

    def for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        rows = self._db.all(
            "SELECT ts, actor, kind, ref_id, detail FROM audit_log WHERE incident_id = ?"
            " ORDER BY id",
            (incident_id,),
        )
        return [
            {
                "ts": r["ts"],
                "actor": r["actor"],
                "kind": r["kind"],
                "ref_id": r["ref_id"],
                "detail": loads(r["detail"]),
            }
            for r in rows
        ]
