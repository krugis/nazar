"""Human approvals: request, approve (with a policy re-check), reject, expire (LLD 10).

Shared by the Telegram buttons and the CLI. It lives at the top level, like ``pipeline``,
because it wires policy, actuator and notifier together.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum

from nazar.actuator import Actuator, ApplyResult, ApplyStatus
from nazar.config import Config
from nazar.core.clock import Clock
from nazar.core.log import get_logger
from nazar.core.net import IpMatcher
from nazar.models import Actor, ApprovalStatus, Decision, Incident, Outcome, Verdict
from nazar.notify import ApprovalNote, FanoutNotifier, UserAction
from nazar.policy import PolicyInput, evaluate
from nazar.store import Store

log = get_logger(__name__)


class ApprovalOutcome(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    REFUSED = "refused"
    """The human approved but the policy re-check did not allow the action."""
    EXPIRED = "expired"
    NOT_PENDING = "not_pending"
    NOT_FOUND = "not_found"


@dataclass(frozen=True)
class ApprovalResult:
    outcome: ApprovalOutcome
    approval_id: str
    reasons: list[str] = field(default_factory=list)
    applied: ApplyResult | None = None


class ApprovalService:
    def __init__(
        self,
        cfg: Config,
        store: Store,
        clock: Clock,
        allowlist: IpMatcher,
        actuator: Actuator,
        notifier: FanoutNotifier,
    ) -> None:
        self._cfg = cfg
        self._store = store
        self._clock = clock
        self._allowlist = allowlist
        self._actuator = actuator
        self._notifier = notifier

    # ------------------------------------------------------------------ request

    async def request(
        self, incident: Incident, verdict: Verdict, decision: Decision, decision_id: int
    ) -> str:
        ttl = timedelta(minutes=self._cfg.notifier.approval_ttl_minutes)
        approval = self._store.approvals.create(decision_id, ttl)
        self._store.audit.append(
            Actor.POLICY,
            "approval",
            {"status": "pending", "expires_at": approval.expires_at.isoformat()},
            incident_id=incident.incident_id,
            ref_id=approval.approval_id,
        )
        note = ApprovalNote(
            incident_id=incident.incident_id,
            ip=incident.source_ip,
            scenarios=incident.scenarios,
            action=decision.action.value,
            duration=decision.duration,
            verdict=verdict.verdict.value,
            severity=verdict.severity.value,
            confidence=verdict.confidence,
            summary=verdict.summary,
            reasoning_points=verdict.reasoning_points,
            policy_reasons=decision.reasons,
            approval_id=approval.approval_id,
            expires_at=approval.expires_at,
        )
        ref = await self._notifier.send(note)
        if ref:
            self._store.approvals.set_message_ref(approval.approval_id, ref)
        log.info("approval_requested", incident_id=incident.incident_id,
                 approval_id=approval.approval_id)  # fmt: skip
        return approval.approval_id

    # ------------------------------------------------------------------ resolve

    async def _edit(self, approval_id: str, text: str) -> None:
        ref = self._store.approvals.message_ref(approval_id)
        if ref:
            await self._notifier.mark_resolved(ref, text)

    def _audit(
        self, incident_id: str, approval_id: str, by: str, status: str, **extra: object
    ) -> None:
        self._store.audit.append(
            by, "approval", {"status": status, **extra}, incident_id=incident_id, ref_id=approval_id
        )

    def _reevaluate(self, decision_id: int, by: str) -> tuple[Incident, int, Decision] | None:
        store = self._store
        row = store.decisions.get(decision_id)
        verdict_row = store.verdicts.get(row.verdict_id) if row else None
        if row is None or verdict_row is None:
            return None
        incident = Incident.model_validate(verdict_row.record.input)
        # Current CrowdSec state, not the state at request time.
        events = store.events.for_incident(row.incident_id)
        incident.crowdsec_already_banned = any("ban" in e.crowdsec_decisions for e in events)
        since = self._clock.now() - timedelta(hours=1)
        inp = PolicyInput(
            incident=incident,
            verdict=verdict_row.record.verdict,
            allowlist_match=None,
            auto_enforced_last_hour=store.decisions.count_auto_enforced(since),
            approved_by=by,
        )
        decision = evaluate(inp, self._cfg.policy, self._cfg.mode, self._allowlist)
        return incident, row.verdict_id, decision

    async def approve(self, approval_id: str, by: str) -> ApprovalResult:
        store = self._store
        approval = store.approvals.get(approval_id)
        if approval is None:
            return ApprovalResult(ApprovalOutcome.NOT_FOUND, approval_id)
        if approval.status is not ApprovalStatus.PENDING:
            return ApprovalResult(ApprovalOutcome.NOT_PENDING, approval_id, [approval.status.value])
        if self._clock.now() >= approval.expires_at:
            await self.expire_due()
            return ApprovalResult(ApprovalOutcome.EXPIRED, approval_id)

        evaluated = self._reevaluate(approval.decision_id, by)
        if evaluated is None:
            return ApprovalResult(ApprovalOutcome.NOT_FOUND, approval_id)
        incident, verdict_id, decision = evaluated
        if decision.outcome is not Outcome.AUTO or not decision.action.enforces:
            if store.approvals.resolve(approval_id, ApprovalStatus.REJECTED, f"policy:{by}"):
                self._audit(
                    incident.incident_id, approval_id, by, "refused_by_policy",
                    reasons=decision.reasons,
                )  # fmt: skip
                why = "; ".join(decision.reasons[-2:])
                await self._edit(
                    approval_id, f"[Nazar] Approval {approval_id}: refused by policy ({why})"
                )
            log.warning("approval_refused_by_policy", approval_id=approval_id, by=by)
            return ApprovalResult(ApprovalOutcome.REFUSED, approval_id, decision.reasons)

        if not store.approvals.resolve(approval_id, ApprovalStatus.APPROVED, by):
            return ApprovalResult(ApprovalOutcome.NOT_PENDING, approval_id)  # lost a race
        with store.transaction():
            new_id = store.decisions.add(incident.incident_id, verdict_id, decision)
            self._audit(incident.incident_id, approval_id, by, "approved", decision_id=new_id)
            store.audit.append(
                Actor.POLICY, "decision", decision.model_dump(mode="json"),
                incident_id=incident.incident_id, ref_id=new_id,
            )  # fmt: skip
        applied = await self._actuator.apply(new_id)
        state = "applied" if applied.status is not ApplyStatus.REFUSED else "NOT applied"
        await self._edit(approval_id, f"[Nazar] Approval {approval_id}: approved by {by}, "
                         f"{decision.action.value} {incident.source_ip} {state}")  # fmt: skip
        log.info("approval_approved", approval_id=approval_id, by=by, applied=applied.status.value)
        return ApprovalResult(ApprovalOutcome.APPROVED, approval_id, decision.reasons, applied)

    async def reject(self, approval_id: str, by: str) -> ApprovalResult:
        approval = self._store.approvals.get(approval_id)
        if approval is None:
            return ApprovalResult(ApprovalOutcome.NOT_FOUND, approval_id)
        if not self._store.approvals.resolve(approval_id, ApprovalStatus.REJECTED, by):
            return ApprovalResult(ApprovalOutcome.NOT_PENDING, approval_id, [approval.status.value])
        self._audit(approval.incident_id, approval_id, by, "rejected")
        await self._edit(approval_id, f"[Nazar] Approval {approval_id}: rejected by {by}")
        log.info("approval_rejected", approval_id=approval_id, by=by)
        return ApprovalResult(ApprovalOutcome.REJECTED, approval_id)

    async def expire_due(self) -> int:
        expired = self._store.approvals.expire_due()
        for approval in expired:
            self._audit(approval.incident_id, approval.approval_id, Actor.SYSTEM, "expired")
            text = f"[Nazar] Approval {approval.approval_id} expired: no action taken"
            await self._edit(approval.approval_id, text)
            log.info("approval_expired", approval_id=approval.approval_id)
        return len(expired)

    # ------------------------------------------------------------------ buttons

    async def handle(self, action: UserAction) -> None:
        """Carry out a verified button click."""
        if action.op == "a":
            await self.approve(action.ref, action.user)
        elif action.op == "r":
            await self.reject(action.ref, action.user)
        elif action.op == "b" and action.ref.isdigit():
            rows = self._actuator.select(decision_id=int(action.ref))
            if rows:
                await self._actuator.rollback(rows, by=action.user)
            if action.message_ref:
                text = (f"[Nazar] decision {action.ref} rolled back by {action.user}" if rows
                        else f"[Nazar] decision {action.ref}: nothing to roll back")  # fmt: skip
                await self._notifier.mark_resolved(action.message_ref, text)
