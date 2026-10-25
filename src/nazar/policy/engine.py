"""Policy engine: verdict + incident → decision (LLD 08).

Pure: no I/O, no clock, no randomness. Same input, same output.
"""

from __future__ import annotations

from nazar.config import Mode, PolicyConfig
from nazar.models import Decision, Outcome
from nazar.policy.rules import RULES
from nazar.policy.types import Draft, IpMatcher, PolicyInput


def evaluate(
    inp: PolicyInput, cfg: PolicyConfig, mode: Mode, allowlist: IpMatcher | None = None
) -> Decision:
    draft = Draft(action=inp.verdict.proposed_action, outcome=Outcome.NO_ACTION)
    for rule in RULES:
        rule(inp, cfg, allowlist, draft)
        if draft.final:
            break
    if not draft.action.enforces:
        draft.duration = None

    # R11 mode gate. Applied last so dry-run reports can show what active mode would do;
    # the final outcome equals DESIGN's order (mode gate second) because report_only is terminal.
    intended = draft.outcome
    outcome = intended
    if mode is Mode.DRY_RUN and intended is not Outcome.NO_ACTION:
        outcome = Outcome.REPORT_ONLY
        draft.reasons.append(f"R11 dry-run: would be {intended.value}")
    return Decision(
        action=draft.action,
        outcome=outcome,
        intended_outcome=intended,
        duration=draft.duration,
        reasons=draft.reasons,
        warnings=draft.warnings,
        unusual_volume=draft.unusual_volume,
    )
