from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from nazar.models.enums import Action, ApprovalStatus, Outcome


class Decision(BaseModel):
    """Output of the policy engine for one verdict."""

    action: Action
    outcome: Outcome
    intended_outcome: Outcome
    """What active mode would do. Equals ``outcome`` in active mode."""
    duration: str | None = None
    reasons: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    unusual_volume: bool = False


class AppliedDecision(BaseModel):
    """A CrowdSec decision created by Nazar."""

    decision_id: int
    incident_id: str
    crowdsec_alert_id: str
    ip: str
    type: Action
    duration: str
    applied_at: datetime
    rolled_back_at: datetime | None = None


class Approval(BaseModel):
    approval_id: str
    decision_id: int
    incident_id: str
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus
    resolved_by: str | None = None
