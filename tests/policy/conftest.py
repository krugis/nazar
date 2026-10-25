from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from nazar.models import Enrichment, History, Incident, Verdict
from nazar.policy import PolicyInput

TS = datetime(2026, 10, 25, 17, 0, tzinfo=UTC)


def make_input(
    *,
    verdict: str = "malicious",
    severity: str = "high",
    confidence: float = 0.9,
    action: str = "ban",
    duration: str | None = "4h",
    ip: str = "203.0.113.45",
    scenarios: tuple[str, ...] = ("crowdsecurity/ssh-bf",),
    cti: str | None = "malicious",
    previous_incidents: int = 0,
    previous_bans: int = 0,
    banned: bool = False,
    allowlist_match: str | None = None,
    budget_used: int = 0,
    approved_by: str | None = None,
) -> PolicyInput:
    incident = Incident(
        incident_id="inc_2026_10_25_0001",
        source_ip=ip,
        first_seen=TS,
        last_seen=TS,
        scenarios=list(scenarios),
        event_count=10,
        enrichment=Enrichment(
            cti_reputation=cti,
            history=History(previous_incidents=previous_incidents, previous_bans=previous_bans),
        ),
        crowdsec_already_banned=banned,
    )
    raw: dict[str, Any] = {
        "verdict": verdict,
        "severity": severity,
        "confidence": confidence,
        "summary": "s",
        "proposed_action": action,
        "proposed_duration": duration,
    }
    return PolicyInput(
        incident=incident,
        verdict=Verdict.model_validate(raw),
        allowlist_match=allowlist_match,
        auto_enforced_last_hour=budget_used,
        approved_by=approved_by,
    )
