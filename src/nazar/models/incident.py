from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class History(BaseModel):
    previous_incidents: int = 0
    previous_bans: int = 0


class Enrichment(BaseModel):
    """Context gathered for an incident. Missing data stays ``None``/empty, never guessed."""

    cti_reputation: str | None = None
    cti_behaviors: list[str] = Field(default_factory=list)
    cti_classifications: list[str] = Field(default_factory=list)
    country: str | None = None
    asn: str | None = None
    history: History = Field(default_factory=History)


class Incident(BaseModel):
    """Events from one source IP grouped in a time window (DESIGN §4.1)."""

    incident_id: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    scenarios: list[str]
    event_count: int
    sample_lines: list[str] = Field(default_factory=list)
    enrichment: Enrichment = Field(default_factory=Enrichment)
    host_context: dict[str, list[str]] = Field(default_factory=dict)
    crowdsec_already_banned: bool = False

    def model_input(self) -> dict[str, Any]:
        """The JSON-ready shape embedded in the model prompt."""
        return self.model_dump(mode="json")
