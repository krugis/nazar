"""Daily summary (LLD 10): built from store queries, rendered as plain text."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from nazar.core.clock import to_iso
from nazar.models import Severity
from nazar.store import Store

TOP_N = 5


def build_summary(store: Store, since: datetime, now: datetime) -> dict[str, Any]:
    incidents = store.incidents.list(since, limit=100_000)
    verdicts = store.verdicts.since(since)
    model_verdicts = [v for v in verdicts if v.record.skipped_reason is None]
    decisions = store.decisions.since(since)
    approvals = store.approvals.since(since)
    latest: dict[str, Any] = {}
    for v in verdicts:
        latest[v.incident_id] = v
    top = sorted(
        (v for v in latest.values() if v.record.skipped_reason is None),
        key=lambda v: (Severity(v.record.verdict.severity).rank, v.record.verdict.confidence),
        reverse=True,
    )[:TOP_N]
    invalid = sum(v.record.invalid_output for v in model_verdicts)
    unavailable = sum(v.record.model_unavailable for v in model_verdicts)
    return {
        "from": to_iso(since),
        "to": to_iso(now),
        "incidents": len(incidents),
        "model_triaged": len(model_verdicts),
        "skipped": dict(
            Counter(v.record.skipped_reason for v in verdicts if v.record.skipped_reason)
        ),
        "verdicts": dict(Counter(v.record.verdict.verdict.value for v in latest.values())),
        "outcomes": dict(Counter(d.decision.outcome.value for d in decisions)),
        "intended_outcomes": dict(Counter(d.decision.intended_outcome.value for d in decisions)),
        "applied": sum(d.applied_at is not None for d in decisions),
        "rolled_back": sum(d.rolled_back_at is not None for d in decisions),
        "approvals": dict(Counter(a.status.value for a in approvals)),
        "invalid_output_pct": round(100.0 * invalid / len(model_verdicts), 1)
        if model_verdicts
        else 0.0,
        "model_unavailable": unavailable,
        "top": [
            {
                "incident_id": v.incident_id,
                "verdict": v.record.verdict.verdict.value,
                "severity": v.record.verdict.severity.value,
                "confidence": v.record.verdict.confidence,
                "ip": (v.record.input or {}).get("source_ip"),
            }
            for v in top
        ],
    }


def _counts(values: dict[str, int]) -> str:
    return ", ".join(f"{k} {n}" for k, n in sorted(values.items())) or "none"


def render_summary(s: dict[str, Any]) -> str:
    lines = [
        f"{s['from']} → {s['to']}",
        f"Incidents: {s['incidents']} ({s['model_triaged']} triaged by the model)",
        f"Verdicts: {_counts(s['verdicts'])}",
        f"Outcomes: {_counts(s['outcomes'])}",
        f"Would be (active mode): {_counts(s['intended_outcomes'])}",
        f"Bans applied: {s['applied']}, rolled back: {s['rolled_back']}",
        f"Approvals: {_counts(s['approvals'])}",
        f"Model invalid output: {s['invalid_output_pct']}%"
        + (
            f" (plus {s['model_unavailable']} not triaged: model unavailable)"
            if s.get("model_unavailable")
            else ""
        ),
    ]
    if s["skipped"]:
        lines.append(f"Not sent to the model: {_counts(s['skipped'])}")
    if s["top"]:
        lines.append("Top incidents:")
        lines += [
            f" {t['incident_id']} {t['ip']} {t['verdict']}/{t['severity']} {t['confidence']:.2f}"
            for t in s["top"]
        ]
    return "\n".join(lines)
