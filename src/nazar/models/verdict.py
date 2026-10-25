from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from nazar.models.durations import VERDICT_DURATION_RE
from nazar.models.enums import Action, Severity, VerdictLabel

SUMMARY_MAX = 400
REASON_MAX = 200
TACTIC_MAX = 80
MAX_REASONS = 5
MAX_TACTICS = 10

Tactic = Annotated[str, StringConstraints(max_length=TACTIC_MAX)]
Reason = Annotated[str, StringConstraints(max_length=REASON_MAX)]


class Verdict(BaseModel):
    """Model output (DESIGN §4.2). Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid")

    verdict: VerdictLabel
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    attack_tactics: list[Tactic] = Field(default_factory=list, max_length=MAX_TACTICS)
    summary: str = Field(max_length=SUMMARY_MAX)
    reasoning_points: list[Reason] = Field(default_factory=list, max_length=MAX_REASONS)
    proposed_action: Action
    proposed_duration: str | None = None

    @field_validator("proposed_duration")
    @classmethod
    def _check_duration(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        if not VERDICT_DURATION_RE.match(value):
            raise ValueError(r"proposed_duration must match ^\d+(m|h)$")
        return value

    @classmethod
    def unknown(cls, reason: str) -> Verdict:
        """Fallback used when the model is unavailable or its output is invalid."""
        return cls(
            verdict=VerdictLabel.UNKNOWN,
            severity=Severity.LOW,
            confidence=0.0,
            summary=reason[:SUMMARY_MAX],
            proposed_action=Action.NONE,
        )


def _enum(values: type[VerdictLabel] | type[Severity] | type[Action]) -> dict[str, Any]:
    return {"type": "string", "enum": [v.value for v in values]}


# Flat schema (no $ref) for Ollama's ``format`` field. Kept equivalent to ``Verdict`` by a test.
VERDICT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": _enum(VerdictLabel),
        "severity": _enum(Severity),
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "attack_tactics": {
            "type": "array",
            "items": {"type": "string", "maxLength": TACTIC_MAX},
            "maxItems": MAX_TACTICS,
        },
        "summary": {"type": "string", "maxLength": SUMMARY_MAX},
        "reasoning_points": {
            "type": "array",
            "items": {"type": "string", "maxLength": REASON_MAX},
            "maxItems": MAX_REASONS,
        },
        "proposed_action": _enum(Action),
        "proposed_duration": {"type": "string", "pattern": r"^(\d+(m|h))?$"},
    },
    "required": [
        "verdict",
        "severity",
        "confidence",
        "attack_tactics",
        "summary",
        "reasoning_points",
        "proposed_action",
        "proposed_duration",
    ],
    "additionalProperties": False,
}
