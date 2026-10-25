"""Guarantees 1-6 from docs/lld/08-policy.md over a grid of inputs."""

from __future__ import annotations

import itertools

import pytest

from nazar.config import Mode, PolicyConfig
from nazar.models import Outcome, parse_duration
from nazar.policy import evaluate
from tests.policy.conftest import make_input

GRID = list(
    itertools.product(
        ["malicious", "suspicious", "benign", "unknown"],
        ["low", "medium", "high", "critical"],
        [0.0, 0.59, 0.6, 0.84, 0.85, 1.0],
        ["none", "notify", "ban", "captcha"],
        [Mode.DRY_RUN, Mode.ACTIVE],
        [None, "config"],
        [0, 20],
        [None, "user:1"],
    )
)
CFG = PolicyConfig(captcha_available=True, auto_actions=["ban", "captcha", "notify"])


def _eval(params: tuple, **extra):  # type: ignore[no-untyped-def,type-arg]
    verdict, severity, conf, action, mode, allow, budget, approver = params
    inp = make_input(
        verdict=verdict,
        severity=severity,
        confidence=conf,
        action=action,
        duration="48h" if action in ("ban", "captcha") else None,
        allowlist_match=allow,
        budget_used=budget,
        approved_by=approver,
        **extra,
    )
    return evaluate(inp, CFG, mode)


@pytest.mark.parametrize("cti", [None, "malicious"])
def test_guarantees(cti: str | None) -> None:
    for params in GRID:
        _, _, _, _, mode, allow, budget, approver = params
        d = _eval(params, cti=cti)
        # 1 allow-listed → no_action
        if allow:
            assert d.outcome is Outcome.NO_ACTION and d.intended_outcome is Outcome.NO_ACTION
        # 2 dry-run never acts
        if mode is Mode.DRY_RUN:
            assert d.outcome in (Outcome.REPORT_ONLY, Outcome.NO_ACTION)
        # 3 bounded durations on enforcing decisions
        if d.action.enforces and d.intended_outcome in (Outcome.AUTO, Outcome.APPROVAL):
            assert d.duration is not None
        if d.duration is not None:
            assert d.action.enforces
            assert parse_duration(d.duration) <= CFG.max_ban
        # 4 single scenario without CTI/history never auto-enforces without a human
        if cti is None and approver is None and d.action.enforces:
            assert d.intended_outcome is not Outcome.AUTO
        # 5 exhausted budget never auto-enforces without a human
        if budget >= CFG.max_auto_actions_per_hour and approver is None and d.action.enforces:
            assert d.intended_outcome is not Outcome.AUTO
        # 6 deterministic
        assert _eval(params, cti=cti) == d
