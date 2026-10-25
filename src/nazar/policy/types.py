"""Policy engine inputs and working state (LLD 08)."""

from __future__ import annotations

from dataclasses import dataclass, field

from nazar.core.net import IpMatcher
from nazar.models import Action, Incident, Outcome, Verdict

__all__ = ["Draft", "IpMatcher", "PolicyInput"]


@dataclass(frozen=True)
class PolicyInput:
    incident: Incident
    verdict: Verdict
    allowlist_match: str | None
    """Result of the pre-filter's allow-list check. The engine re-checks on its own too."""
    auto_enforced_last_hour: int = 0
    """Applied automatic ban/captcha decisions in the last 60 minutes."""
    approved_by: str | None = None
    """Set when re-evaluating at the moment a human approves (R10)."""


@dataclass
class Draft:
    """Mutable working copy that rules refine in order."""

    action: Action
    outcome: Outcome
    duration: str | None = None
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unusual_volume: bool = False
    final: bool = False

    def set(self, outcome: Outcome, reason: str, *, final: bool = False) -> None:
        self.outcome = outcome
        self.reasons.append(reason)
        self.final = self.final or final
