"""Table-driven tests for rules R1-R11 (docs/lld/08-policy.md)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from nazar.config import Mode, PolicyConfig
from nazar.models import Action, Outcome
from nazar.policy import evaluate
from nazar.prefilter import build_allowlist
from tests.policy.conftest import make_input

A, P, R, N = Outcome.AUTO, Outcome.APPROVAL, Outcome.REPORT_ONLY, Outcome.NO_ACTION


@dataclass(frozen=True)
class Case:
    name: str
    inp: dict[str, Any]
    outcome: Outcome
    action: Action | None = None
    duration: str | None = "keep"
    mode: Mode = Mode.ACTIVE
    intended: Outcome | None = None
    reason: str | None = None
    cfg: dict[str, Any] = field(default_factory=dict)
    unusual_volume: bool = False


CASES = [
    # R1 hard deny
    Case("allowlisted by prefilter", {"allowlist_match": "config"}, N, reason="R1"),
    Case("protected rfc1918", {"ip": "10.0.0.5"}, N, reason="rfc1918"),
    Case("protected loopback v6", {"ip": "::1"}, N, reason="loopback"),
    Case(
        "config cidr",
        {"ip": "198.51.100.9"},
        N,
        reason="config",
        cfg={"allowlist_cidrs": ["198.51.100.0/24"]},
    ),
    Case("not an ip", {"ip": "203.0.113.0/24"}, N, reason="not a single IP"),
    Case("allowlisted even if approved", {"allowlist_match": "host", "approved_by": "user:1"}, N),
    # R2 whitelist
    Case("captcha without bouncer", {"action": "captcha"}, N, reason="R2"),
    Case(
        "captcha with bouncer",
        {"action": "captcha"},
        A,
        cfg={"captcha_available": True, "auto_actions": ["captcha"]},
    ),
    # R3
    Case("action none", {"action": "none", "duration": None}, N, reason="R3"),
    Case(
        "unknown fallback verdict",
        {
            "verdict": "unknown",
            "action": "none",
            "confidence": 0.0,
            "severity": "low",
            "duration": None,
        },
        N,
    ),
    # R4 consistency
    Case("benign but ban", {"verdict": "benign"}, R, reason="R4"),
    Case("unknown but ban", {"verdict": "unknown"}, R, reason="R4"),
    Case("benign notify ok", {"verdict": "benign", "action": "notify", "duration": None}, A),
    # R5 already enforced
    Case("crowdsec already bans", {"banned": True}, R, reason="R5"),
    Case("crowdsec bans, notify still fine", {"banned": True, "action": "notify"}, A),
    # R6 bounds
    Case("duration clamped", {"duration": "72h"}, A, duration="24h"),
    Case("default duration", {"duration": None}, A, duration="4h"),
    Case("minutes kept", {"duration": "90m"}, A, duration="90m"),
    Case("notify has no duration", {"action": "notify"}, A, duration=None),
    Case(
        "custom max",
        {"duration": "12h"},
        A,
        duration="6h",
        cfg={"max_ban_duration": "6h", "default_ban_duration": "1h"},
    ),
    # R7 thresholds
    Case("auto at exactly 0.85", {"confidence": 0.85}, A),
    Case("approval at 0.84", {"confidence": 0.84}, P),
    Case("approval at exactly 0.6", {"confidence": 0.6}, P),
    Case("report at 0.59", {"confidence": 0.59}, R),
    Case("medium severity needs approval", {"severity": "medium", "confidence": 0.99}, P),
    Case("critical auto", {"severity": "critical"}, A),
    Case("ban not in auto_actions", {}, P, cfg={"auto_actions": ["notify"]}),
    Case("notify auto at 0.6", {"action": "notify", "confidence": 0.6, "severity": "low"}, A),
    Case("notify below threshold", {"action": "notify", "confidence": 0.5}, R),
    Case("notify not auto action", {"action": "notify"}, R, cfg={"auto_actions": ["ban"]}),
    # R8 corroboration
    Case("no corroboration", {"cti": None}, P, reason="R8"),
    Case("cti suspicious is not enough", {"cti": "suspicious"}, P, reason="R8"),
    Case("two scenarios", {"cti": None, "scenarios": ("a", "b")}, A),
    Case("duplicate scenario names count once", {"cti": None, "scenarios": ("a", "a")}, P),
    Case("previous incident", {"cti": None, "previous_incidents": 1}, A),
    Case("previous ban", {"cti": None, "previous_bans": 1}, A),
    # R9 budget
    Case("budget available", {"budget_used": 19}, A),
    Case("budget exhausted", {"budget_used": 20}, P, reason="R9", unusual_volume=True),
    Case("zero budget", {}, P, cfg={"max_auto_actions_per_hour": 0}, unusual_volume=True),
    # R10 human approval
    Case("approved", {"confidence": 0.7, "approved_by": "user:42"}, A, reason="R10"),
    Case(
        "approved over budget",
        {"budget_used": 99, "approved_by": "user:42"},
        A,
        unusual_volume=True,
    ),
    Case("approval cannot raise report_only", {"confidence": 0.3, "approved_by": "user:1"}, R),
    Case("approval cannot bypass R4", {"verdict": "benign", "approved_by": "user:1"}, R),
    Case("approval cannot bypass R5", {"banned": True, "approved_by": "user:1"}, R),
    # R11 mode gate
    Case("dry-run auto", {}, R, mode=Mode.DRY_RUN, intended=A, reason="R11"),
    Case("dry-run approval", {"confidence": 0.7}, R, mode=Mode.DRY_RUN, intended=P),
    Case(
        "dry-run no_action stays",
        {"action": "none", "duration": None},
        N,
        mode=Mode.DRY_RUN,
        intended=N,
    ),
    Case("dry-run allowlisted", {"ip": "127.0.0.1"}, N, mode=Mode.DRY_RUN, intended=N),
]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_rule_table(case: Case) -> None:
    cfg = PolicyConfig(**case.cfg)
    allow = build_allowlist(cfg, host_addresses=[])
    inp = make_input(**case.inp)
    d = evaluate(inp, cfg, case.mode, allow)
    assert d.outcome is case.outcome, d.reasons
    assert d.intended_outcome is (case.intended or case.outcome)
    if case.action is not None:
        assert d.action is case.action
    if case.duration != "keep":
        assert d.duration == case.duration
    if case.reason:
        assert any(case.reason in r for r in d.reasons), d.reasons
    assert d.unusual_volume is case.unusual_volume


def test_reasons_explain_the_path() -> None:
    d = evaluate(make_input(), PolicyConfig(), Mode.DRY_RUN)
    assert [r.split()[0] for r in d.reasons] == ["R7", "R8", "R11"]


def test_warning_on_clamp_and_inconsistency() -> None:
    d = evaluate(make_input(duration="72h"), PolicyConfig(), Mode.ACTIVE)
    assert any("clamped" in w for w in d.warnings)
    d2 = evaluate(make_input(verdict="benign"), PolicyConfig(), Mode.ACTIVE)
    assert any("benign" in w for w in d2.warnings)
