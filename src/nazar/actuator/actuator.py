"""Apply and roll back Nazar's CrowdSec decisions (LLD 09)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from nazar.actuator.backend import BanRequest, DecisionBackend
from nazar.config import Config, Mode
from nazar.core.clock import Clock
from nazar.core.log import get_logger
from nazar.core.net import IpMatcher
from nazar.models import Actor, Outcome, parse_duration
from nazar.store import DecisionRow, Store

log = get_logger(__name__)


class ApplyStatus(StrEnum):
    APPLIED = "applied"
    ALREADY_APPLIED = "already_applied"
    REFUSED = "refused"


@dataclass(frozen=True)
class ApplyResult:
    status: ApplyStatus
    decision_id: int
    crowdsec_alert_id: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class RollbackResult:
    decision_id: int
    incident_id: str
    ip: str
    removed: int


def idempotency_key(incident_id: str, action: str, ip: str) -> str:
    return hashlib.sha256(f"{incident_id}|{action}|{ip}".encode()).hexdigest()


class Actuator:
    def __init__(
        self,
        cfg: Config,
        store: Store,
        backend: DecisionBackend,
        allowlist: IpMatcher,
        clock: Clock,
    ) -> None:
        self._cfg = cfg
        self._store = store
        self._backend = backend
        self._allowlist = allowlist
        self._clock = clock

    # ------------------------------------------------------------------ apply

    def _refusal(self, row: DecisionRow) -> str | None:
        """Last-line guards. Any hit means a caller bug, never a normal path."""
        d = row.decision
        if self._cfg.mode is not Mode.ACTIVE:
            return "not in active mode"
        if d.outcome is not Outcome.AUTO:
            return f"outcome is {d.outcome.value}, not auto"
        if not d.action.enforces:
            return f"action {d.action.value} does not enforce"
        if not d.duration or parse_duration(d.duration) > self._cfg.policy.max_ban:
            return "missing or unbounded duration"
        label = self._allowlist.match(row.source_ip)
        if label is not None:
            return f"source is allow-listed ({label})"
        return None

    async def apply(self, decision_id: int) -> ApplyResult:
        store = self._store
        row = store.decisions.get(decision_id)
        if row is None:
            return ApplyResult(ApplyStatus.REFUSED, decision_id, reason="no such decision")
        reason = self._refusal(row)
        if reason is not None:
            log.error("actuator_refused", decision_id=decision_id, reason=reason)
            store.audit.append(
                Actor.SYSTEM, "refused", {"reason": reason}, row.incident_id, decision_id
            )
            return ApplyResult(ApplyStatus.REFUSED, decision_id, reason=reason)

        key = idempotency_key(row.incident_id, row.decision.action.value, row.source_ip)
        existing = store.decisions.by_idempotency_key(key)
        if existing is not None and existing.id != decision_id:
            if existing.rolled_back_at is not None:
                reason = "an earlier decision for this incident was rolled back"
                return ApplyResult(ApplyStatus.REFUSED, decision_id, reason=reason)
            if existing.applied_at is not None:
                return ApplyResult(
                    ApplyStatus.ALREADY_APPLIED, existing.id, existing.crowdsec_alert_id
                )
            row = existing  # an earlier attempt crashed half-way: finish that one
        elif existing is None:
            store.decisions.set_idempotency_key(decision_id, key)
        elif row.applied_at is not None:
            return ApplyResult(ApplyStatus.ALREADY_APPLIED, row.id, row.crowdsec_alert_id)
        return await self._push(row)

    def _request(self, row: DecisionRow) -> BanRequest:
        assert row.decision.duration is not None
        return BanRequest(
            ip=row.source_ip,
            type=row.decision.action,
            duration=row.decision.duration,
            incident_id=row.incident_id,
            decision_id=row.id,
        )

    async def _push(self, row: DecisionRow) -> ApplyResult:
        req = self._request(row)
        alert_id = await self._backend.find(req) if row.idempotency_key else None
        if alert_id is None:
            alert_id = await self._backend.add(req)
        with self._store.transaction():
            self._store.decisions.mark_applied(row.id, alert_id)
            self._store.audit.append(
                Actor.SYSTEM,
                "applied",
                {"type": req.type.value, "ip": req.ip, "duration": req.duration,
                 "crowdsec_alert_id": alert_id},
                row.incident_id,
                row.id,
            )  # fmt: skip
        log.info(
            "decision_applied",
            decision_id=row.id,
            incident_id=row.incident_id,
            ip=req.ip,
            type=req.type.value,
            duration=req.duration,
            crowdsec_alert_id=alert_id,
        )
        return ApplyResult(ApplyStatus.APPLIED, row.id, alert_id)

    async def reconcile(self) -> int:
        """At startup: finish decisions keyed but never recorded as applied (crash)."""
        done = 0
        for row in self._store.decisions.unapplied_auto():
            if self._refusal(row) is not None:
                continue
            await self._push(row)
            done += 1
        return done

    # ------------------------------------------------------------------ rollback

    def select(
        self,
        *,
        decision_id: int | None = None,
        incident_id: str | None = None,
        since: timedelta | None = None,
    ) -> list[DecisionRow]:
        """Applied, not yet rolled back decisions matching exactly one selector."""
        if sum(x is not None for x in (decision_id, incident_id, since)) != 1:
            raise ValueError("give exactly one of decision_id, incident_id, since")
        if decision_id is not None:
            row = self._store.decisions.get(decision_id)
            ok = row is not None and row.applied_at is not None and row.rolled_back_at is None
            return [row] if ok and row is not None else []
        start: datetime | None = self._clock.now() - since if since is not None else None
        return self._store.decisions.applied(since=start, incident_id=incident_id)

    async def rollback(self, rows: list[DecisionRow], by: str) -> list[RollbackResult]:
        results: list[RollbackResult] = []
        for row in rows:
            removed = await self._backend.remove(row.crowdsec_alert_id or "", row.source_ip)
            with self._store.transaction():
                self._store.decisions.mark_rolled_back(row.id, by)
                self._store.audit.append(
                    by, "rollback", {"removed": removed, "ip": row.source_ip},
                    row.incident_id, row.id,
                )  # fmt: skip
            log.info("decision_rolled_back", decision_id=row.id, ip=row.source_ip, by=by,
                     removed=removed)  # fmt: skip
            results.append(RollbackResult(row.id, row.incident_id, row.source_ip, removed))
        return results
