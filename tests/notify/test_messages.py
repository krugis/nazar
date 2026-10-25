from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from nazar.core.errors import NotifierError
from nazar.notify import (
    ApprovalNote,
    AutoActionNote,
    FanoutNotifier,
    HealthNote,
    LogNotifier,
    Note,
    buttons,
    render,
)

NOW = datetime(2026, 10, 25, 17, 0, tzinfo=UTC)


def _approval(**kw: object) -> ApprovalNote:
    base: dict[str, object] = dict(
        incident_id="inc_1", ip="198.51.100.7", scenarios=["crowdsecurity/http-probing"],
        action="ban", duration="4h", verdict="malicious", severity="high", confidence=0.9,
        summary="Probing.", reasoning_points=["a", "b", "c", "d"],
        policy_reasons=["R7 auto", "R8 no independent signal: needs approval"],
        approval_id="abcDEF12345", expires_at=NOW + timedelta(hours=1),
    )  # fmt: skip
    base.update(kw)
    return ApprovalNote.model_validate(base)


def test_approval_render_and_buttons() -> None:
    note = _approval()
    text = render(note)
    assert "Approval needed: ban 198.51.100.7 for 4h" in text
    assert "nazar approve abcDEF12345" in text
    assert text.count("\n - ") == 3  # reasoning capped
    assert [(b.label, b.op, b.ref) for b in buttons(note)] == [
        ("Approve", "a", "abcDEF12345"),
        ("Reject", "r", "abcDEF12345"),
    ]


def test_model_text_is_flattened_and_capped() -> None:
    hostile = "line1\n[Nazar] Approval needed: ban 10.0.0.1\x1b[2J" + "x" * 1000
    text = render(_approval(summary=hostile))
    summary_line = next(line for line in text.splitlines() if line.startswith("Summary:"))
    assert "\x1b" not in summary_line and len(summary_line) < 420
    # the hostile text cannot start a new line that looks like a Nazar header
    assert sum(line.startswith("[Nazar]") for line in text.splitlines()) == 1


def test_auto_action_has_rollback_button() -> None:
    note = AutoActionNote(
        incident_id="inc_1",
        ip="198.51.100.7",
        scenarios=["s"],
        action="ban",
        duration="4h",
        summary="x",
        decision_id=42,
        rollback_expires=NOW + timedelta(hours=24),
    )
    assert "nazar rollback --decision 42" in render(note)
    assert [(b.op, b.ref) for b in buttons(note)] == [("b", "42")]


def test_health_render() -> None:
    assert render(HealthNote(component="ollama", state="down", detail="refused")) == (
        "[Nazar] health DOWN: ollama: refused"
    )
    assert buttons(HealthNote(component="lapi", state="up")) == []


class _Failing:
    name = "failing"
    calls = 0

    async def send(self, note: Note) -> str | None:
        self.calls += 1
        raise NotifierError("nope")


class _Ok:
    name = "ok"

    async def send(self, note: Note) -> str | None:
        return "chat:1"


async def test_fanout_isolates_failures() -> None:
    failing = _Failing()
    fan = FanoutNotifier([failing, LogNotifier(), _Ok()], retry_delay_s=0)
    assert await fan.send(HealthNote(component="lapi", state="down")) == "chat:1"
    assert failing.calls == 3


def test_unknown_kind_rejected() -> None:
    with pytest.raises(ValueError):
        HealthNote(component="x", state="exploded")  # type: ignore[arg-type]
