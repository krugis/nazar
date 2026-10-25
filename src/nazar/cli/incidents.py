"""``nazar incidents``, ``nazar explain``, ``nazar report``."""

from __future__ import annotations

import argparse
import asyncio
from typing import Any

from nazar.app import build_app
from nazar.cli import _context
from nazar.cli._output import err, print_json, print_table
from nazar.cli._store import open_store
from nazar.config import Config
from nazar.core.clock import SystemClock, to_iso
from nazar.models import parse_duration
from nazar.notify import TextNote, build_summary, render_summary
from nazar.store import Store


def register(sub: Any) -> None:
    p = sub.add_parser("incidents", help="list incidents and verdicts")
    p.add_argument("--since", default="24h", help="look-back window, e.g. 1h, 24h, 7d")
    p.add_argument("--ip", help="only this source IP")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(handler=cmd_incidents)

    r = sub.add_parser("report", help="print (and optionally send) the summary")
    r.add_argument("--daily", action="store_true", help="the last 24 hours (default)")
    r.add_argument("--since", default="24h", help="look-back window, e.g. 24h, 7d")
    r.add_argument("--send", action="store_true", help="also send it through the notifiers")
    r.set_defaults(handler=cmd_report)

    e = sub.add_parser("explain", help="full reasoning trail of one incident")
    e.add_argument("incident_id")
    e.set_defaults(handler=cmd_explain)


def _summary(store: Store, incident_id: str) -> dict[str, Any]:
    verdict = store.verdicts.latest(incident_id)
    decisions = store.decisions.for_incident(incident_id)
    last = decisions[-1] if decisions else None
    return {
        "verdict": verdict.record.verdict.verdict.value if verdict else None,
        "severity": verdict.record.verdict.severity.value if verdict else None,
        "confidence": verdict.record.verdict.confidence if verdict else None,
        "action": last.decision.action.value if last else None,
        "outcome": last.decision.outcome.value if last else None,
        "intended": last.decision.intended_outcome.value if last else None,
        "applied": any(d.applied_at and not d.rolled_back_at for d in decisions),
        "skipped": verdict.record.skipped_reason if verdict else None,
    }


def cmd_incidents(args: argparse.Namespace) -> int:
    cfg = _context.load(args)
    store = open_store(cfg)
    try:
        since = SystemClock().now() - parse_duration(args.since)
        rows = store.incidents.list(since, source_ip=args.ip, limit=args.limit)
        items = [
            {
                "id": r.id,
                "ip": r.source_ip,
                "status": r.status.value,
                "last_seen": to_iso(r.last_seen),
                "events": r.event_count,
                "scenarios": r.scenarios,
                "pending_triage": r.needs_triage,
            }
            | _summary(store, r.id)
            for r in rows
        ]
    finally:
        store.close()
    if args.json:
        print_json(items)
        return 0
    if not items:
        print(f"no incidents in the last {args.since}")
        return 0
    print_table(
        ["id", "ip", "last seen", "scenarios", "verdict", "conf", "outcome", "applied"],
        [
            [
                i["id"],
                i["ip"],
                i["last_seen"],
                ",".join(s.split("/")[-1] for s in i["scenarios"]),
                f"{i['verdict']}/{i['severity']}" if i["verdict"] else "pending",
                f"{i['confidence']:.2f}" if i["confidence"] is not None else "",
                i["outcome"] or "",
                "yes" if i["applied"] else "",
            ]
            for i in items
        ],
    )
    return 0


def explain_data(store: Store, incident_id: str) -> dict[str, Any] | None:
    inc = store.incidents.get(incident_id)
    if inc is None:
        return None
    return {
        "incident": {
            "id": inc.id,
            "ip": inc.source_ip,
            "status": inc.status.value,
            "first_seen": to_iso(inc.first_seen),
            "last_seen": to_iso(inc.last_seen),
            "events": inc.event_count,
            "scenarios": inc.scenarios,
        },
        "events": [
            {
                "alert_id": e.alert_id,
                "scenario": e.scenario,
                "first_ts": to_iso(e.first_ts),
                "count": e.event_count,
                "merged_alerts": e.merged_alerts,
                "crowdsec_decisions": e.crowdsec_decisions,
                "sample_lines": e.sample_lines,
            }
            for e in store.events.for_incident(incident_id)
        ],
        "verdicts": [
            {
                "id": v.id,
                "at": to_iso(v.created_at),
                "model": v.record.model,
                "prompt_version": v.record.prompt_version,
                "valid_output": v.record.valid_output,
                "attempts": v.record.attempts,
                "latency_ms": v.record.latency_ms,
                "skipped": v.record.skipped_reason,
                "verdict": v.record.verdict.model_dump(mode="json"),
                "enrichment": v.record.input.get("enrichment"),
            }
            for v in store.verdicts.for_incident(incident_id)
        ],
        "decisions": [
            {
                "id": d.id,
                "verdict_id": d.verdict_id,
                **d.decision.model_dump(mode="json"),
                "applied_at": to_iso(d.applied_at) if d.applied_at else None,
                "crowdsec_alert_id": d.crowdsec_alert_id,
                "rolled_back_at": to_iso(d.rolled_back_at) if d.rolled_back_at else None,
                "rolled_back_by": d.rolled_back_by,
            }
            for d in store.decisions.for_incident(incident_id)
        ],
        "audit": store.audit.for_incident(incident_id),
    }


def _print_explain(data: dict[str, Any]) -> None:
    inc = data["incident"]
    print(f"Incident {inc['id']}  {inc['ip']}  ({inc['status']})")
    print(f"  {inc['first_seen']} → {inc['last_seen']}, {inc['events']} events")
    print(f"  scenarios: {', '.join(inc['scenarios'])}")
    print("\nEvents")
    for e in data["events"]:
        merged = f", {e['merged_alerts']} alerts merged" if e["merged_alerts"] > 1 else ""
        banned = (
            " [CrowdSec: " + ",".join(e["crowdsec_decisions"]) + "]"
            if e["crowdsec_decisions"]
            else ""
        )
        print(f"  #{e['alert_id']} {e['scenario']} x{e['count']}{merged}{banned}")
        for line in e["sample_lines"][:5]:
            print(f"      {line}")
    for v in data["verdicts"]:
        verdict = v["verdict"]
        print(f"\nVerdict #{v['id']} at {v['at']}")
        if v["skipped"]:
            print(f"  model not called: {v['skipped']}")
        else:
            print(f"  model {v['model']} prompt {v['prompt_version']}, attempts {v['attempts']}, "
                  f"{v['latency_ms']} ms, valid output: {v['valid_output']}")  # fmt: skip
        print(
            f"  {verdict['verdict']} / {verdict['severity']} / confidence {verdict['confidence']}"
        )
        print(f"  proposed: {verdict['proposed_action']} {verdict['proposed_duration'] or ''}")
        print(f"  summary: {verdict['summary']}")
        for point in verdict["reasoning_points"]:
            print(f"   - {point}")
        if verdict["attack_tactics"]:
            print(f"  tactics: {', '.join(verdict['attack_tactics'])}")
        enr = v["enrichment"] or {}
        if enr:
            hist = enr.get("history") or {}
            print(f"  enrichment: cti={enr.get('cti_reputation')} country={enr.get('country')} "
                  f"asn={enr.get('asn')} previous incidents={hist.get('previous_incidents')} "
                  f"bans={hist.get('previous_bans')}")  # fmt: skip
    for d in data["decisions"]:
        print(f"\nDecision #{d['id']}: {d['action']} → {d['outcome']} "
              f"(would be {d['intended_outcome']}) {d['duration'] or ''}")  # fmt: skip
        for reason in d["reasons"]:
            print(f"   - {reason}")
        for warning in d["warnings"]:
            print(f"   ! {warning}")
        if d["applied_at"]:
            print(f"  applied {d['applied_at']} (CrowdSec alert {d['crowdsec_alert_id']})")
        if d["rolled_back_at"]:
            print(f"  rolled back {d['rolled_back_at']} by {d['rolled_back_by']}")
    print("\nAudit")
    for a in data["audit"]:
        print(f"  {a['ts']} {a['actor']:<14} {a['kind']:<9} {a['ref_id'] or ''}")


def cmd_explain(args: argparse.Namespace) -> int:
    cfg = _context.load(args)
    store = open_store(cfg)
    try:
        data = explain_data(store, args.incident_id)
    finally:
        store.close()
    if data is None:
        err(f"no incident {args.incident_id}")
        return 1
    if args.json:
        print_json(data)
    else:
        _print_explain(data)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    cfg = _context.load(args)
    now = SystemClock().now()
    window = parse_duration("24h" if args.daily else args.since)
    store = open_store(cfg)
    try:
        summary = build_summary(store, now - window, now)
    finally:
        store.close()
    if args.json:
        print_json(summary)
    else:
        print(render_summary(summary))
    if args.send:
        asyncio.run(_send(cfg, render_summary(summary)))
    return 0


async def _send(cfg: Config, text: str) -> None:
    app = build_app(cfg)
    try:
        await app.notifier.send(TextNote(kind="daily_summary", title="Summary", text=text))
    finally:
        await app.aclose()
