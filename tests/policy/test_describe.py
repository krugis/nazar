"""Plain-language description of what Nazar did, used in incident notes."""

from __future__ import annotations

import pytest

from nazar.config import Mode, PolicyConfig
from nazar.pipeline import describe_action
from nazar.policy import evaluate
from tests.policy.conftest import make_input


@pytest.mark.parametrize(
    ("inp", "mode", "expected"),
    [
        ({"action": "notify", "confidence": 0.75, "severity": "medium"}, Mode.ACTIVE,
         "notification only (this message); no ban needed"),
        ({"banned": True}, Mode.ACTIVE, "no extra ban: CrowdSec already blocks this IP"),
        ({"verdict": "benign"}, Mode.ACTIVE, "reported only: the verdict does not justify a ban"),
        ({"confidence": 0.3}, Mode.ACTIVE, "reported only: confidence too low to act"),
        ({"action": "notify", "confidence": 0.75}, Mode.DRY_RUN,
         "dry-run, nothing changed; active mode would send a notification"),
        ({}, Mode.DRY_RUN, "dry-run, nothing changed; active mode would ban (auto)"),
    ],
)  # fmt: skip
def test_describe_action(inp: dict[str, object], mode: Mode, expected: str) -> None:
    decision = evaluate(make_input(**inp), PolicyConfig(), mode)  # type: ignore[arg-type]
    assert describe_action(decision) == expected
