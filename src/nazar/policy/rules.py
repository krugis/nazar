"""Policy rules R1-R10, in evaluation order (LLD 08). The mode gate R11 lives in the engine.

Each rule inspects the input and refines the draft. A rule that marks the draft ``final``
skips the remaining rules. Adding a rule: one function here, one entry in ``RULES``, rows in
the test table and in docs/lld/08-policy.md.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable

from nazar.config import PolicyConfig
from nazar.models import Action, Outcome, Severity, VerdictLabel, format_duration, parse_duration
from nazar.policy.types import Draft, IpMatcher, PolicyInput

Rule = Callable[[PolicyInput, PolicyConfig, IpMatcher | None, Draft], None]


def _is_single_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def r1_hard_deny(inp: PolicyInput, cfg: PolicyConfig, allow: IpMatcher | None, d: Draft) -> None:
    ip = inp.incident.source_ip
    if not _is_single_ip(ip):
        d.set(Outcome.NO_ACTION, "R1 hard deny: source is not a single IP address", final=True)
        return
    label = inp.allowlist_match or (allow.match(ip) if allow is not None else None)
    if label is not None:
        d.set(Outcome.NO_ACTION, f"R1 hard deny: source is allow-listed ({label})", final=True)


def r2_action_whitelist(
    inp: PolicyInput, cfg: PolicyConfig, allow: IpMatcher | None, d: Draft
) -> None:
    if not isinstance(d.action, Action):  # unreachable through the Verdict schema; a guard
        d.warnings.append(f"action {d.action!r} is not allowed")
        d.action = Action.NONE
        d.set(Outcome.NO_ACTION, "R2 action whitelist: unknown action", final=True)
    elif d.action is Action.CAPTCHA and not cfg.captcha_available:
        d.warnings.append("captcha proposed but no captcha-capable bouncer is configured")
        d.set(Outcome.NO_ACTION, "R2 action whitelist: captcha unavailable", final=True)


def r3_nothing_to_do(
    inp: PolicyInput, cfg: PolicyConfig, allow: IpMatcher | None, d: Draft
) -> None:
    if d.action is Action.NONE:
        d.set(Outcome.NO_ACTION, "R3 no action proposed", final=True)


def r4_verdict_consistency(
    inp: PolicyInput, cfg: PolicyConfig, allow: IpMatcher | None, d: Draft
) -> None:
    verdict = inp.verdict.verdict
    if d.action.enforces and verdict in (VerdictLabel.BENIGN, VerdictLabel.UNKNOWN):
        d.warnings.append(f"model proposed {d.action.value} with verdict {verdict.value}")
        d.set(Outcome.REPORT_ONLY, "R4 verdict does not support enforcement", final=True)


def r5_already_enforced(
    inp: PolicyInput, cfg: PolicyConfig, allow: IpMatcher | None, d: Draft
) -> None:
    if d.action.enforces and inp.incident.crowdsec_already_banned:
        d.set(Outcome.REPORT_ONLY, "R5 CrowdSec already bans this IP", final=True)


def r6_bounds(inp: PolicyInput, cfg: PolicyConfig, allow: IpMatcher | None, d: Draft) -> None:
    if not d.action.enforces:
        d.duration = None
        return
    proposed = inp.verdict.proposed_duration
    duration = parse_duration(proposed) if proposed else cfg.default_ban
    if duration > cfg.max_ban:
        d.warnings.append(f"duration {proposed} clamped to {cfg.max_ban_duration}")
        duration = cfg.max_ban
    d.duration = format_duration(duration)


def r7_thresholds(inp: PolicyInput, cfg: PolicyConfig, allow: IpMatcher | None, d: Draft) -> None:
    v = inp.verdict
    allowed_auto = d.action in cfg.auto_actions
    if d.action is Action.NOTIFY:
        if v.confidence >= cfg.approval_min_confidence and allowed_auto:
            d.set(Outcome.AUTO, "R7 notify: confidence above approval threshold")
        else:
            d.set(Outcome.REPORT_ONLY, "R7 notify: below threshold or not an auto action")
        return
    if (
        v.confidence >= cfg.auto_min_confidence
        and v.severity.rank >= Severity.HIGH.rank
        and allowed_auto
    ):
        d.set(Outcome.AUTO, f"R7 auto: confidence {v.confidence:.2f}, severity {v.severity.value}")
    elif v.confidence >= cfg.approval_min_confidence:
        d.set(Outcome.APPROVAL, f"R7 approval: confidence {v.confidence:.2f}")
    else:
        d.set(Outcome.REPORT_ONLY, f"R7 report only: confidence {v.confidence:.2f} too low")


def r8_corroboration(
    inp: PolicyInput, cfg: PolicyConfig, allow: IpMatcher | None, d: Draft
) -> None:
    if d.outcome is not Outcome.AUTO or not d.action.enforces:
        return
    enrichment = inp.incident.enrichment
    signals = []
    if enrichment.cti_reputation == "malicious":
        signals.append("CTI malicious")
    if len(set(inp.incident.scenarios)) >= 2:
        signals.append("multiple scenarios")
    if enrichment.history.previous_incidents >= 1:
        signals.append("previous incidents")
    if enrichment.history.previous_bans >= 1:
        signals.append("previous bans")
    if signals:
        d.reasons.append("R8 corroborated by " + ", ".join(signals))
    else:
        d.set(Outcome.APPROVAL, "R8 no independent signal: needs approval")


def r9_budget(inp: PolicyInput, cfg: PolicyConfig, allow: IpMatcher | None, d: Draft) -> None:
    if d.outcome is not Outcome.AUTO or not d.action.enforces:
        return
    if inp.auto_enforced_last_hour >= cfg.max_auto_actions_per_hour:
        d.unusual_volume = True
        d.set(
            Outcome.APPROVAL,
            f"R9 budget of {cfg.max_auto_actions_per_hour} automatic actions per hour reached",
        )


def r10_human_approval(
    inp: PolicyInput, cfg: PolicyConfig, allow: IpMatcher | None, d: Draft
) -> None:
    if inp.approved_by and d.outcome is Outcome.APPROVAL:
        d.set(Outcome.AUTO, f"R10 approved by {inp.approved_by}")


RULES: tuple[Rule, ...] = (
    r1_hard_deny,
    r2_action_whitelist,
    r3_nothing_to_do,
    r4_verdict_consistency,
    r5_already_enforced,
    r6_bounds,
    r7_thresholds,
    r8_corroboration,
    r9_budget,
    r10_human_approval,
)
