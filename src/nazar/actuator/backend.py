"""Decision backend interface (LLD 09)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from nazar.models import Action

CSCLI_REF = "cscli"
"""``crowdsec_alert_id`` recorded for decisions created through the cscli fallback."""


@dataclass(frozen=True)
class BanRequest:
    ip: str
    type: Action
    duration: str
    incident_id: str
    decision_id: int

    @property
    def message(self) -> str:
        """Alert message; also how a half-applied decision is found again after a crash."""
        return (
            f"nazar {self.incident_id} decision {self.decision_id}: "
            f"{self.type.value} {self.ip} for {self.duration}"
        )


class DecisionBackend(Protocol):
    async def add(self, req: BanRequest) -> str:
        """Create the decision in CrowdSec. Returns the CrowdSec alert ID."""
        ...

    async def remove(self, crowdsec_alert_id: str, ip: str) -> int:
        """Remove the decisions Nazar created. Returns how many CrowdSec deleted."""
        ...

    async def find(self, req: BanRequest) -> str | None:
        """Alert ID of an already-pushed request, if CrowdSec has it (crash reconcile)."""
        ...
