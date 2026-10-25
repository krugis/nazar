from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class Event(BaseModel):
    """One normalized CrowdSec alert. All text fields are already sanitized."""

    model_config = ConfigDict(frozen=True)

    alert_id: int
    source_ip: str
    scenario: str
    started_at: datetime
    stopped_at: datetime
    event_count: int = 1
    message: str = ""
    sample_lines: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    country: str | None = None
    asn: str | None = None
    crowdsec_decisions: list[str] = Field(default_factory=list)
    """Types of active decisions CrowdSec attached to the alert, e.g. ``["ban"]``."""
