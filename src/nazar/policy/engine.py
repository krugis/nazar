"""M1 placeholder for the policy engine: report only, never act.

Replaced by the full rule set R1-R11 in M2 (TRACKER P-1). The interface is final.
"""

from __future__ import annotations

from dataclasses import dataclass

from nazar.config import Mode, PolicyConfig
from nazar.models import Decision, Incident, Outcome, Verdict


@dataclass(frozen=True)
class PolicyInput:
    incident: Incident
    verdict: Verdict
    allowlist_match: str | None
    auto_enforced_last_hour: int = 0
    approved_by: str | None = None


def evaluate(inp: PolicyInput, cfg: PolicyConfig, mode: Mode) -> Decision:
    action = inp.verdict.proposed_action
    if inp.allowlist_match is not None:
        return Decision(
            action=action,
            outcome=Outcome.NO_ACTION,
            intended_outcome=Outcome.NO_ACTION,
            reasons=[f"R1 hard deny: source is allow-listed ({inp.allowlist_match})"],
        )
    return Decision(
        action=action,
        outcome=Outcome.REPORT_ONLY,
        intended_outcome=Outcome.REPORT_ONLY,
        reasons=["policy engine not implemented yet (M2): report only"],
    )
