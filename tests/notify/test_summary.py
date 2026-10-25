from __future__ import annotations

from datetime import timedelta

from nazar.core.clock import FrozenClock
from nazar.models import Action, Decision, Outcome, Verdict
from nazar.notify import build_summary, render_summary
from nazar.store import Store, VerdictRecord


def test_summary_counts(store: Store, clock: FrozenClock) -> None:
    inc = store.incidents.create("198.51.100.7", clock.now())
    good = Verdict.model_validate(
        {
            "verdict": "malicious",
            "severity": "high",
            "confidence": 0.9,
            "summary": "s",
            "proposed_action": "ban",
        }
    )
    vid = store.verdicts.add(
        inc.id, VerdictRecord(good, "m", "triage-v1", input={"source_ip": "198.51.100.7"})
    )
    store.verdicts.add(
        inc.id, VerdictRecord(Verdict.unknown("x"), "m", "triage-v1", valid_output=False)
    )
    d = Decision(
        action=Action.BAN, outcome=Outcome.AUTO, intended_outcome=Outcome.AUTO, duration="4h"
    )
    store.decisions.mark_applied(store.decisions.add(inc.id, vid, d), "1")
    other = store.incidents.create("192.0.2.1", clock.now())
    store.verdicts.add(
        other.id,
        VerdictRecord(Verdict.unknown("x"), "none", "none", skipped_reason="allowlisted:config"),
    )
    s = build_summary(store, clock.now() - timedelta(hours=24), clock.now())
    assert s["incidents"] == 2 and s["model_triaged"] == 2
    assert s["applied"] == 1 and s["outcomes"] == {"auto": 1}
    assert s["invalid_output_pct"] == 50.0
    assert s["skipped"] == {"allowlisted:config": 1}
    text = render_summary(s)
    assert "Bans applied: 1" in text and "Incidents: 2" in text
