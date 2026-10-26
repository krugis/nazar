"""Notification types and plain-text rendering (LLD 10).

Rendering is plain text with fixed templates: model text (which read attacker data) can never
add formatting, links or buttons. Model-written fields are capped here as well.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from nazar.core.clock import to_iso
from nazar.core.sanitize import clean_line

_SUMMARY_MAX = 400
_REASON_MAX = 200
_MAX_REASONS = 3


class _Note(BaseModel):
    pass


class AutoActionNote(_Note):
    kind: Literal["auto_action"] = "auto_action"
    incident_id: str
    ip: str
    scenarios: list[str]
    action: str
    duration: str | None
    summary: str
    decision_id: int
    rollback_expires: datetime


class ApprovalNote(_Note):
    kind: Literal["approval"] = "approval"
    incident_id: str
    ip: str
    scenarios: list[str]
    action: str
    duration: str | None
    verdict: str
    severity: str
    confidence: float
    summary: str
    reasoning_points: list[str] = Field(default_factory=list)
    policy_reasons: list[str] = Field(default_factory=list)
    approval_id: str
    expires_at: datetime


class IncidentNote(_Note):
    """A notify action or a high-severity report-only incident."""

    kind: Literal["incident"] = "incident"
    incident_id: str
    ip: str
    scenarios: list[str]
    verdict: str
    severity: str
    confidence: float
    summary: str
    outcome: str
    crowdsec_blocking: bool = False
    """CrowdSec already has an active ban on this IP (enforced by its bouncers)."""
    nazar_did: str = ""
    """What Nazar did about it, in plain words."""


class TextNote(_Note):
    """Pre-rendered text built by Nazar itself (daily summary, reports)."""

    kind: Literal["daily_summary", "report"] = "report"
    title: str
    text: str


class HealthNote(_Note):
    kind: Literal["health"] = "health"
    component: str
    state: Literal["down", "up", "warning"]
    detail: str = ""


Note = AutoActionNote | ApprovalNote | IncidentNote | TextNote | HealthNote


@dataclass(frozen=True)
class Button:
    label: str
    op: Literal["a", "r", "b"]
    """``a`` approve, ``r`` reject, ``b`` rollback."""
    ref: str
    expires: datetime


def _model_text(text: str, limit: int = _SUMMARY_MAX) -> str:
    return clean_line(text, limit)


def _scenarios(scenarios: list[str]) -> str:
    return ", ".join(clean_line(s, 80) for s in scenarios[:5])


def render(n: Note) -> str:
    if isinstance(n, AutoActionNote):
        return (
            f"[Nazar] {n.action.upper()} applied: {n.ip} for {n.duration}\n"
            f"Incident {n.incident_id}\n"
            f"Scenarios: {_scenarios(n.scenarios)}\n"
            f"Why: {_model_text(n.summary)}\n"
            f"Roll back: nazar rollback --decision {n.decision_id}"
        )
    if isinstance(n, ApprovalNote):
        points = "".join(
            f"\n - {_model_text(p, _REASON_MAX)}" for p in n.reasoning_points[:_MAX_REASONS]
        )
        policy = "".join(f"\n * {clean_line(r, _REASON_MAX)}" for r in n.policy_reasons[-2:])
        return (
            f"[Nazar] Approval needed: {n.action} {n.ip} for {n.duration}\n"
            f"Incident {n.incident_id}\n"
            f"Scenarios: {_scenarios(n.scenarios)}\n"
            f"Verdict: {n.verdict} / {n.severity} / confidence {n.confidence:.2f}\n"
            f"Summary: {_model_text(n.summary)}{points}\n"
            f"Policy:{policy}\n"
            f"Expires {to_iso(n.expires_at)}. CLI: nazar approve {n.approval_id}"
        )
    if isinstance(n, IncidentNote):
        crowdsec = "already blocking this IP" if n.crowdsec_blocking else "not blocking this IP"
        return (
            f"[Nazar] {n.severity.upper()} incident {n.incident_id}: {n.ip}\n"
            f"Scenarios: {_scenarios(n.scenarios)}\n"
            f"Verdict: {n.verdict} / confidence {n.confidence:.2f}\n"
            f"CrowdSec: {crowdsec}\n"
            f"Nazar: {clean_line(n.nazar_did, 200) or n.outcome}\n"
            f"Summary: {_model_text(n.summary)}"
        )
    if isinstance(n, TextNote):
        return f"[Nazar] {n.title}\n{n.text}"
    icon = {"down": "DOWN", "up": "recovered", "warning": "warning"}[n.state]
    detail = f": {clean_line(n.detail, 300)}" if n.detail else ""
    return f"[Nazar] health {icon}: {n.component}{detail}"


def buttons(n: Note) -> list[Button]:
    if isinstance(n, AutoActionNote):
        return [Button("Rollback", "b", str(n.decision_id), n.rollback_expires)]
    if isinstance(n, ApprovalNote):
        return [
            Button("Approve", "a", n.approval_id, n.expires_at),
            Button("Reject", "r", n.approval_id, n.expires_at),
        ]
    return []
