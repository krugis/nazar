"""Processing of one incident: enrich → analyse → decide (→ act in M2) (LLD 11)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta

from nazar.actuator import Actuator, ApplyResult, ApplyStatus
from nazar.analyst import Analyst
from nazar.approvals import ApprovalService
from nazar.config import Config
from nazar.core.clock import Clock
from nazar.core.log import get_logger
from nazar.core.net import IpMatcher
from nazar.enrich import Enricher
from nazar.models import Action, Actor, Decision, Incident, Outcome, Severity, Verdict
from nazar.notify import AutoActionNote, FanoutNotifier, IncidentNote
from nazar.policy import PolicyInput, evaluate
from nazar.store import EventRow, IncidentRow, Store, VerdictRecord

log = get_logger(__name__)

SKIP_MODEL = "none"


@dataclass(frozen=True)
class PipelineResult:
    incident: Incident
    verdict: Verdict
    decision: Decision | None
    skipped_reason: str | None = None
    valid_output: bool = True
    decision_id: int | None = None
    applied: ApplyResult | None = None
    approval_id: str | None = None


def build_incident(inc: IncidentRow, events: Sequence[EventRow], cfg: Config) -> Incident:
    lines: list[str] = []
    for event in events:
        for line in event.sample_lines:
            if len(lines) >= cfg.prefilter.max_sample_lines:
                break
            lines.append(line)
    host_context = {"exposed_services": list(cfg.host_context.exposed_services)}
    return Incident(
        incident_id=inc.id,
        source_ip=inc.source_ip,
        first_seen=inc.first_seen,
        last_seen=inc.last_seen,
        scenarios=list(inc.scenarios),
        event_count=inc.event_count,
        sample_lines=lines,
        host_context=host_context,
        crowdsec_already_banned=any("ban" in e.crowdsec_decisions for e in events),
    )


class Pipeline:
    def __init__(
        self,
        cfg: Config,
        store: Store,
        clock: Clock,
        allowlist: IpMatcher,
        enricher: Enricher,
        analyst: Analyst,
        actuator: Actuator | None = None,
        approvals: ApprovalService | None = None,
        notifier: FanoutNotifier | None = None,
    ) -> None:
        self._actuator = actuator
        self._approvals = approvals
        self._notifier = notifier
        self._cfg = cfg
        self._store = store
        self._clock = clock
        self._allowlist = allowlist
        self._enricher = enricher
        self._analyst = analyst

    async def process(self, incident_id: str) -> PipelineResult | None:
        """Triage one incident. Returns None if it no longer exists."""
        store = self._store
        row = store.incidents.get(incident_id)
        if row is None:
            return None
        events = store.events.for_incident(incident_id)
        incident = build_incident(row, events, self._cfg)

        label = self._allowlist.match(incident.source_ip)
        if label is not None:
            return self._skip(incident, f"allowlisted:{label}", allowlist_match=label)
        if incident.crowdsec_already_banned and set(row.scenarios) == set(
            row.last_triaged_scenarios or []
        ):
            return self._skip(incident, "already_banned_no_new_signal")

        incident.enrichment = await self._enricher.enrich(incident, events)
        triage = await self._analyst.triage(incident)
        record = VerdictRecord(
            verdict=triage.verdict,
            model=triage.model,
            prompt_version=triage.prompt_version,
            input=incident.model_input(),
            valid_output=triage.valid_output,
            attempts=triage.attempts,
            latency_ms=triage.latency_ms,
        )
        decision, decision_id = self._decide_and_store(incident, record, label)
        applied, approval_id = await self._carry_out(
            incident, triage.verdict, decision, decision_id
        )
        return PipelineResult(
            incident,
            triage.verdict,
            decision,
            valid_output=triage.valid_output,
            decision_id=decision_id,
            applied=applied,
            approval_id=approval_id,
        )

    async def _carry_out(
        self, incident: Incident, verdict: Verdict, decision: Decision, decision_id: int
    ) -> tuple[ApplyResult | None, str | None]:
        """Act on the policy outcome. Only ``auto`` enforcing decisions touch CrowdSec."""
        if decision.outcome is Outcome.AUTO and decision.action.enforces:
            if self._actuator is None:
                log.error("no_actuator_configured", decision_id=decision_id)
                return None, None
            applied = await self._actuator.apply(decision_id)
            if applied.status is ApplyStatus.APPLIED:
                await self._notify(
                    AutoActionNote(
                        incident_id=incident.incident_id,
                        ip=incident.source_ip,
                        scenarios=incident.scenarios,
                        action=decision.action.value,
                        duration=decision.duration,
                        summary=verdict.summary,
                        decision_id=applied.decision_id,
                        rollback_expires=self._clock.now() + self._cfg.policy.max_ban,
                    )
                )
            return applied, None
        if decision.outcome is Outcome.APPROVAL and self._approvals is not None:
            approval_id = await self._approvals.request(incident, verdict, decision, decision_id)
            return None, approval_id
        notify = decision.action is Action.NOTIFY and decision.outcome is Outcome.AUTO
        serious = (
            decision.outcome is Outcome.REPORT_ONLY and verdict.severity.rank >= Severity.HIGH.rank
        )
        if notify or serious:
            await self._notify(
                IncidentNote(
                    incident_id=incident.incident_id,
                    ip=incident.source_ip,
                    scenarios=incident.scenarios,
                    verdict=verdict.verdict.value,
                    severity=verdict.severity.value,
                    confidence=verdict.confidence,
                    summary=verdict.summary,
                    outcome=decision.intended_outcome.value,
                )
            )
        return None, None

    async def _notify(self, note: AutoActionNote | IncidentNote) -> None:
        if self._notifier is not None:
            await self._notifier.send(note)

    def _decide_and_store(
        self, incident: Incident, record: VerdictRecord, allowlist_match: str | None
    ) -> tuple[Decision, int]:
        store = self._store
        since = self._clock.now() - timedelta(hours=1)
        inp = PolicyInput(
            incident=incident,
            verdict=record.verdict,
            allowlist_match=allowlist_match,
            auto_enforced_last_hour=store.decisions.count_auto_enforced(since),
        )
        decision = evaluate(inp, self._cfg.policy, self._cfg.mode, self._allowlist)
        with store.transaction():
            verdict_id = store.verdicts.add(incident.incident_id, record)
            store.audit.append(
                Actor.MODEL if record.skipped_reason is None else Actor.SYSTEM,
                "verdict",
                {
                    "verdict": record.verdict.verdict.value,
                    "severity": record.verdict.severity.value,
                    "confidence": record.verdict.confidence,
                    "proposed_action": record.verdict.proposed_action.value,
                    "model": record.model,
                    "prompt_version": record.prompt_version,
                    "valid_output": record.valid_output,
                    "skipped": record.skipped_reason,
                },
                incident_id=incident.incident_id,
                ref_id=verdict_id,
            )
            decision_id = store.decisions.add(incident.incident_id, verdict_id, decision)
            store.audit.append(
                Actor.POLICY,
                "decision",
                decision.model_dump(mode="json"),
                incident_id=incident.incident_id,
                ref_id=decision_id,
            )
            store.incidents.mark_triaged(incident.incident_id, incident.scenarios)
        log.info(
            "incident_triaged",
            incident_id=incident.incident_id,
            ip=incident.source_ip,
            verdict=record.verdict.verdict.value,
            confidence=record.verdict.confidence,
            action=decision.action.value,
            outcome=decision.outcome.value,
        )
        return decision, decision_id

    def _skip(
        self, incident: Incident, reason: str, allowlist_match: str | None = None
    ) -> PipelineResult:
        verdict = Verdict.unknown(f"not triaged by the model: {reason}")
        record = VerdictRecord(
            verdict=verdict,
            model=SKIP_MODEL,
            prompt_version=SKIP_MODEL,
            input=incident.model_input(),
            skipped_reason=reason,
        )
        decision, decision_id = self._decide_and_store(incident, record, allowlist_match)
        return PipelineResult(
            incident, verdict, decision, skipped_reason=reason, decision_id=decision_id
        )

    def record_skipped(self, incident_ids: Sequence[str], reason: str) -> None:
        """Record incidents that will not reach the model (rate-limit overflow, failures)."""
        for incident_id in incident_ids:
            row = self._store.incidents.get(incident_id)
            if row is None:
                continue
            events = self._store.events.for_incident(incident_id)
            self._skip(build_incident(row, events, self._cfg), reason)


def report_line(result: PipelineResult) -> str:
    """One human-readable line for dry-run reports."""
    inc, v, d = result.incident, result.verdict, result.decision
    intended = d.intended_outcome.value if d else Outcome.NO_ACTION.value
    action = d.action.value if d else "none"
    extra = f" skipped={result.skipped_reason}" if result.skipped_reason else ""
    if result.applied is not None:
        extra += f" applied={result.applied.status.value}"
    if result.approval_id:
        extra += f" approval={result.approval_id}"
    return (
        f"{inc.incident_id} {inc.source_ip:<15} {','.join(inc.scenarios)} -> {v.verdict.value}"
        f"/{v.severity.value} conf={v.confidence:.2f} action={action} would={intended}{extra}"
    )
