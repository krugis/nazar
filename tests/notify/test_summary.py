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
    unknown = Verdict.unknown("x")
    # an invalid answer (two attempts), a recorded outage, and a pre-v2 outage row (no error
    # value, one attempt, no latency)
    store.verdicts.add(
        inc.id,
        VerdictRecord(
            unknown, "m", "triage-v1", valid_output=False, attempts=2, latency_ms=900,
            error="invalid_output",
        ),
    )  # fmt: skip
    store.verdicts.add(
        inc.id,
        VerdictRecord(unknown, "m", "triage-v1", valid_output=False, attempts=1,
                      error="model_unavailable"),
    )  # fmt: skip
    store.verdicts.add(
        inc.id, VerdictRecord(unknown, "m", "triage-v1", valid_output=False, attempts=1)
    )
    d = Decision(
        action=Action.BAN, outcome=Outcome.AUTO, intended_outcome=Outcome.AUTO, duration="4h"
    )
    store.decisions.mark_applied(store.decisions.add(inc.id, vid, d), "1")
    skipped = Decision(
        action=Action.BAN,
        outcome=Outcome.REPORT_ONLY,
        intended_outcome=Outcome.REPORT_ONLY,
        reasons=["R5 CrowdSec already bans this IP"],
    )
    store.decisions.add(inc.id, vid, skipped)
    other = store.incidents.create("192.0.2.1", clock.now())
    store.verdicts.add(
        other.id,
        VerdictRecord(Verdict.unknown("x"), "none", "none", skipped_reason="allowlisted:config"),
    )
    s = build_summary(store, clock.now() - timedelta(hours=24), clock.now())
    assert s["incidents"] == 2 and s["model_triaged"] == 4
    assert s["applied"] == 1 and s["outcomes"] == {"auto": 1, "report_only": 1}
    assert s["already_banned"] == 1
    assert s["invalid_output_pct"] == 25.0  # 1 of 4 model verdicts
    assert s["model_unavailable"] == 2
    assert s["skipped"] == {"allowlisted:config": 1}
    text = render_summary(s)
    assert "Bans applied by Nazar: 1" in text and "Incidents: 2" in text
    assert "Already banned by CrowdSec (Nazar did not add a ban): 1" in text
    assert "Would be (active mode)" not in text  # same as the outcomes outside dry-run
    assert "plus 2 not triaged: model unavailable" in text
