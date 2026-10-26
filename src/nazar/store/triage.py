"""Verdict, decision and approval repositories (LLD 03)."""

from __future__ import annotations

import secrets
import sqlite3
import string
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from nazar.core.clock import Clock, from_iso, to_iso
from nazar.models import Action, Approval, ApprovalStatus, Decision, Outcome, Verdict
from nazar.store.db import Database, dumps, loads


def _ts(value: str | None) -> datetime | None:
    return from_iso(value) if value else None


ERROR_MODEL_UNAVAILABLE = "model_unavailable"
ERROR_INVALID_OUTPUT = "invalid_output"


@dataclass(frozen=True)
class VerdictRecord:
    """What to store for one triage attempt (model call or skip)."""

    verdict: Verdict
    model: str
    prompt_version: str
    input: dict[str, Any] = field(default_factory=dict)
    valid_output: bool = True
    attempts: int = 0
    latency_ms: int | None = None
    skipped_reason: str | None = None
    error: str | None = None
    """``model_unavailable`` or ``invalid_output`` when the verdict is a fallback."""

    @property
    def model_unavailable(self) -> bool:
        if self.error is not None:
            return self.error == ERROR_MODEL_UNAVAILABLE
        # Rows written before schema v2: an outage fallback made one attempt and has no latency;
        # an invalid answer always took two attempts.
        return (
            not self.valid_output
            and self.skipped_reason is None
            and self.attempts <= 1
            and self.latency_ms is None
        )

    @property
    def invalid_output(self) -> bool:
        return not self.valid_output and self.skipped_reason is None and not self.model_unavailable


@dataclass
class VerdictRow:
    id: int
    incident_id: str
    created_at: datetime
    record: VerdictRecord


class VerdictRepo:
    def __init__(self, db: Database, clock: Clock) -> None:
        self._db = db
        self._clock = clock

    def add(self, incident_id: str, rec: VerdictRecord) -> int:
        v = rec.verdict
        cur = self._db.execute(
            "INSERT INTO verdicts (incident_id, created_at, model, prompt_version, verdict,"
            " severity, confidence, proposed_action, body, input, valid_output, attempts,"
            " latency_ms, skipped_reason, error)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                incident_id,
                to_iso(self._clock.now()),
                rec.model,
                rec.prompt_version,
                v.verdict.value,
                v.severity.value,
                v.confidence,
                v.proposed_action.value,
                v.model_dump_json(),
                dumps(rec.input),
                int(rec.valid_output),
                rec.attempts,
                rec.latency_ms,
                rec.skipped_reason,
                rec.error,
            ),
        )
        assert cur.lastrowid is not None
        return cur.lastrowid

    @staticmethod
    def _row(row: sqlite3.Row) -> VerdictRow:
        return VerdictRow(
            id=row["id"],
            incident_id=row["incident_id"],
            created_at=from_iso(row["created_at"]),
            record=VerdictRecord(
                verdict=Verdict.model_validate_json(row["body"]),
                model=row["model"],
                prompt_version=row["prompt_version"],
                input=loads(row["input"]),
                valid_output=bool(row["valid_output"]),
                attempts=row["attempts"],
                latency_ms=row["latency_ms"],
                skipped_reason=row["skipped_reason"],
                error=row["error"],
            ),
        )

    def get(self, verdict_id: int) -> VerdictRow | None:
        row = self._db.one("SELECT * FROM verdicts WHERE id = ?", (verdict_id,))
        return self._row(row) if row else None

    def latest(self, incident_id: str) -> VerdictRow | None:
        row = self._db.one(
            "SELECT * FROM verdicts WHERE incident_id = ? ORDER BY id DESC LIMIT 1", (incident_id,)
        )
        return self._row(row) if row else None

    def for_incident(self, incident_id: str) -> list[VerdictRow]:
        rows = self._db.all(
            "SELECT * FROM verdicts WHERE incident_id = ? ORDER BY id", (incident_id,)
        )
        return [self._row(r) for r in rows]

    def since(self, since: datetime) -> list[VerdictRow]:
        rows = self._db.all(
            "SELECT * FROM verdicts WHERE created_at >= ? ORDER BY id", (to_iso(since),)
        )
        return [self._row(r) for r in rows]


@dataclass
class DecisionRow:
    id: int
    incident_id: str
    verdict_id: int
    source_ip: str
    created_at: datetime
    decision: Decision
    idempotency_key: str | None
    applied_at: datetime | None
    crowdsec_alert_id: str | None
    rolled_back_at: datetime | None
    rolled_back_by: str | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> DecisionRow:
        return cls(
            id=row["id"],
            incident_id=row["incident_id"],
            verdict_id=row["verdict_id"],
            source_ip=row["source_ip"],
            created_at=from_iso(row["created_at"]),
            decision=Decision(
                action=Action(row["action"]),
                outcome=Outcome(row["outcome"]),
                intended_outcome=Outcome(row["intended_outcome"]),
                duration=row["duration"],
                reasons=loads(row["reasons"]),
                warnings=loads(row["warnings"]),
            ),
            idempotency_key=row["idempotency_key"],
            applied_at=_ts(row["applied_at"]),
            crowdsec_alert_id=row["crowdsec_alert_id"],
            rolled_back_at=_ts(row["rolled_back_at"]),
            rolled_back_by=row["rolled_back_by"],
        )


_DECISION_SELECT = (
    "SELECT d.*, i.source_ip FROM decisions d JOIN incidents i ON i.id = d.incident_id"
)


class DecisionRepo:
    def __init__(self, db: Database, clock: Clock) -> None:
        self._db = db
        self._clock = clock

    def add(
        self,
        incident_id: str,
        verdict_id: int,
        decision: Decision,
        idempotency_key: str | None = None,
    ) -> int:
        cur = self._db.execute(
            "INSERT INTO decisions (incident_id, verdict_id, created_at, action, outcome,"
            " intended_outcome, duration, reasons, warnings, idempotency_key)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                incident_id,
                verdict_id,
                to_iso(self._clock.now()),
                decision.action.value,
                decision.outcome.value,
                decision.intended_outcome.value,
                decision.duration,
                dumps(decision.reasons),
                dumps(decision.warnings),
                idempotency_key,
            ),
        )
        assert cur.lastrowid is not None
        return cur.lastrowid

    def get(self, decision_id: int) -> DecisionRow | None:
        row = self._db.one(f"{_DECISION_SELECT} WHERE d.id = ?", (decision_id,))
        return DecisionRow.from_row(row) if row else None

    def by_idempotency_key(self, key: str) -> DecisionRow | None:
        row = self._db.one(f"{_DECISION_SELECT} WHERE d.idempotency_key = ?", (key,))
        return DecisionRow.from_row(row) if row else None

    def set_idempotency_key(self, decision_id: int, key: str) -> None:
        self._db.execute(
            "UPDATE decisions SET idempotency_key = ? WHERE id = ?", (key, decision_id)
        )

    def mark_applied(self, decision_id: int, crowdsec_alert_id: str) -> None:
        self._db.execute(
            "UPDATE decisions SET applied_at = ?, crowdsec_alert_id = ? WHERE id = ?",
            (to_iso(self._clock.now()), crowdsec_alert_id, decision_id),
        )

    def mark_rolled_back(self, decision_id: int, by: str) -> None:
        self._db.execute(
            "UPDATE decisions SET rolled_back_at = ?, rolled_back_by = ?"
            " WHERE id = ? AND rolled_back_at IS NULL",
            (to_iso(self._clock.now()), by, decision_id),
        )

    def for_incident(self, incident_id: str) -> list[DecisionRow]:
        rows = self._db.all(
            f"{_DECISION_SELECT} WHERE d.incident_id = ? ORDER BY d.id", (incident_id,)
        )
        return [DecisionRow.from_row(r) for r in rows]

    def applied(
        self,
        since: datetime | None = None,
        incident_id: str | None = None,
        source_ip: str | None = None,
        active_only: bool = True,
    ) -> list[DecisionRow]:
        sql = f"{_DECISION_SELECT} WHERE d.applied_at IS NOT NULL"
        params: list[Any] = []
        if active_only:
            sql += " AND d.rolled_back_at IS NULL"
        if since is not None:
            sql += " AND d.applied_at >= ?"
            params.append(to_iso(since))
        if incident_id is not None:
            sql += " AND d.incident_id = ?"
            params.append(incident_id)
        if source_ip is not None:
            sql += " AND i.source_ip = ?"
            params.append(source_ip)
        return [DecisionRow.from_row(r) for r in self._db.all(sql + " ORDER BY d.id", params)]

    def unapplied_auto(self) -> list[DecisionRow]:
        """Enforcing auto decisions that were keyed but never recorded as applied (crash)."""
        rows = self._db.all(
            f"{_DECISION_SELECT} WHERE d.idempotency_key IS NOT NULL AND d.applied_at IS NULL"
            " AND d.outcome = 'auto' ORDER BY d.id"
        )
        return [DecisionRow.from_row(r) for r in rows]

    def count_auto_enforced(self, since: datetime) -> int:
        row = self._db.one(
            "SELECT COUNT(*) FROM decisions WHERE outcome = 'auto' AND action IN ('ban', 'captcha')"
            " AND applied_at >= ?",
            (to_iso(since),),
        )
        return int(row[0]) if row else 0

    def since(self, since: datetime) -> list[DecisionRow]:
        rows = self._db.all(
            f"{_DECISION_SELECT} WHERE d.created_at >= ? ORDER BY d.id", (to_iso(since),)
        )
        return [DecisionRow.from_row(r) for r in rows]


_ID_ALPHABET = string.ascii_letters + string.digits


def new_approval_id(length: int = 11) -> str:
    """Random letters and digits (about 65 bits). Never starts with ``-``, so it is always a
    plain CLI argument (``nazar approve <id>``)."""
    return "".join(secrets.choice(_ID_ALPHABET) for _ in range(length))


_APPROVAL_SELECT = (
    "SELECT a.*, d.incident_id FROM approvals a JOIN decisions d ON d.id = a.decision_id"
)


def _approval(row: sqlite3.Row) -> Approval:
    return Approval(
        approval_id=row["id"],
        decision_id=row["decision_id"],
        incident_id=row["incident_id"],
        created_at=from_iso(row["created_at"]),
        expires_at=from_iso(row["expires_at"]),
        status=ApprovalStatus(row["status"]),
        resolved_by=row["resolved_by"],
    )


class ApprovalRepo:
    def __init__(self, db: Database, clock: Clock) -> None:
        self._db = db
        self._clock = clock

    def create(self, decision_id: int, ttl: timedelta) -> Approval:
        approval_id = new_approval_id()
        now = self._clock.now()
        self._db.execute(
            "INSERT INTO approvals (id, decision_id, created_at, expires_at, status)"
            " VALUES (?, ?, ?, ?, 'pending')",
            (approval_id, decision_id, to_iso(now), to_iso(now + ttl)),
        )
        approval = self.get(approval_id)
        assert approval is not None
        return approval

    def get(self, approval_id: str) -> Approval | None:
        row = self._db.one(f"{_APPROVAL_SELECT} WHERE a.id = ?", (approval_id,))
        return _approval(row) if row else None

    def resolve(self, approval_id: str, status: ApprovalStatus, by: str) -> bool:
        """Move a pending approval to a final status. Single-shot: False if not pending."""
        cur = self._db.execute(
            "UPDATE approvals SET status = ?, resolved_at = ?, resolved_by = ?"
            " WHERE id = ? AND status = 'pending'",
            (status.value, to_iso(self._clock.now()), by, approval_id),
        )
        return cur.rowcount == 1

    def set_message_ref(self, approval_id: str, ref: str) -> None:
        self._db.execute("UPDATE approvals SET message_ref = ? WHERE id = ?", (ref, approval_id))

    def message_ref(self, approval_id: str) -> str | None:
        row = self._db.one("SELECT message_ref FROM approvals WHERE id = ?", (approval_id,))
        return row["message_ref"] if row else None

    def expire_due(self) -> list[Approval]:
        now = to_iso(self._clock.now())
        with self._db.transaction():
            rows = self._db.all(
                f"{_APPROVAL_SELECT} WHERE a.status = 'pending' AND a.expires_at <= ?", (now,)
            )
            self._db.execute(
                "UPDATE approvals SET status = 'expired', resolved_at = ?, resolved_by = 'system'"
                " WHERE status = 'pending' AND expires_at <= ?",
                (now, now),
            )
        return [_approval(r).model_copy(update={"status": ApprovalStatus.EXPIRED}) for r in rows]

    def pending(self) -> list[Approval]:
        rows = self._db.all(f"{_APPROVAL_SELECT} WHERE a.status = 'pending' ORDER BY a.created_at")
        return [_approval(r) for r in rows]

    def since(self, since: datetime) -> list[Approval]:
        rows = self._db.all(f"{_APPROVAL_SELECT} WHERE a.created_at >= ?", (to_iso(since),))
        return [_approval(r) for r in rows]
