from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from nazar.models import (
    VERDICT_JSON_SCHEMA,
    Action,
    Severity,
    Verdict,
    VerdictLabel,
    format_duration,
    parse_duration,
)

VALID: dict[str, Any] = {
    "verdict": "malicious",
    "severity": "high",
    "confidence": 0.9,
    "attack_tactics": ["TA0006 Credential Access"],
    "summary": "SSH brute force followed by HTTP probing.",
    "reasoning_points": ["57 failed logins", "CTI malicious"],
    "proposed_action": "ban",
    "proposed_duration": "4h",
}


def test_valid_verdict() -> None:
    v = Verdict.model_validate(VALID)
    assert v.verdict is VerdictLabel.MALICIOUS
    assert v.proposed_action is Action.BAN


@pytest.mark.parametrize(
    "patch",
    [
        {"confidence": 1.2},
        {"confidence": -0.1},
        {"summary": "x" * 401},
        {"reasoning_points": ["a"] * 6},
        {"reasoning_points": ["a" * 201]},
        {"extra": "field"},
        {"proposed_duration": "2d"},
        {"proposed_duration": "4 h"},
        {"proposed_action": "shell"},
        {"verdict": "evil"},
        {"severity": "urgent"},
    ],
)
def test_verdict_rejects(patch: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Verdict.model_validate({**VALID, **patch})


def test_empty_duration_normalized() -> None:
    assert Verdict.model_validate({**VALID, "proposed_duration": ""}).proposed_duration is None


def test_unknown_fallback() -> None:
    v = Verdict.unknown("model unavailable")
    assert v.verdict is VerdictLabel.UNKNOWN
    assert v.proposed_action is Action.NONE
    assert v.confidence == 0.0


def test_schema_matches_model() -> None:
    props = VERDICT_JSON_SCHEMA["properties"]
    assert set(props) == set(Verdict.model_fields)
    assert set(VERDICT_JSON_SCHEMA["required"]) == set(Verdict.model_fields)
    assert props["verdict"]["enum"] == [v.value for v in VerdictLabel]
    assert props["severity"]["enum"] == [v.value for v in Severity]
    assert props["proposed_action"]["enum"] == [v.value for v in Action]
    assert VERDICT_JSON_SCHEMA["additionalProperties"] is False
    assert "$ref" not in str(VERDICT_JSON_SCHEMA)


def test_severity_rank_and_enforces() -> None:
    assert Severity.LOW.rank < Severity.HIGH.rank < Severity.CRITICAL.rank
    assert Action.BAN.enforces and Action.CAPTCHA.enforces
    assert not Action.NOTIFY.enforces and not Action.NONE.enforces


@pytest.mark.parametrize(
    ("text", "seconds"), [("30s", 30), ("5m", 300), ("4h", 14400), ("1d", 86400)]
)
def test_parse_duration(text: str, seconds: int) -> None:
    assert parse_duration(text).total_seconds() == seconds


@pytest.mark.parametrize("text", ["4 h", "-1h", "h", "1w", ""])
def test_parse_duration_rejects(text: str) -> None:
    with pytest.raises(ValueError):
        parse_duration(text)


def test_format_duration() -> None:
    assert format_duration(timedelta(hours=4)) == "4h"
    assert format_duration(timedelta(minutes=90)) == "90m"
    assert format_duration(timedelta(seconds=45)) == "45s"
    with pytest.raises(ValueError):
        format_duration(timedelta(0))
