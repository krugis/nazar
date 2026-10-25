"""Deduplication and grouping of events into incidents (LLD 05).

The caller wraps ``ingest`` and the collector cursor commit in one store transaction.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timedelta

from nazar.config import PrefilterConfig
from nazar.core.log import get_logger
from nazar.core.net import IpMatcher
from nazar.models import Actor, Event, Verdict
from nazar.store import IncidentRow, Store, VerdictRecord

log = get_logger(__name__)

SKIP_MODEL = "none"


@dataclass
class IngestResult:
    needs_triage: list[str] = field(default_factory=list)
    """Incident IDs that gained a new signal in this batch."""
    new_incidents: int = 0
    merged_alerts: int = 0
    allowlisted: int = 0


class Grouper:
    def __init__(self, store: Store, allowlist: IpMatcher, cfg: PrefilterConfig) -> None:
        self._store = store
        self._allowlist = allowlist
        self._cfg = cfg

    def ingest(self, events: Sequence[Event]) -> IngestResult:
        result = IngestResult()
        triage: dict[str, None] = {}  # ordered set
        for event in sorted(events, key=lambda e: e.alert_id):
            incident_id = self._ingest_one(event, result)
            if incident_id:
                triage[incident_id] = None
        result.needs_triage = list(triage)
        return result

    def _ingest_one(self, event: Event, result: IngestResult) -> str | None:
        store = self._store
        window = timedelta(minutes=self._cfg.incident_window_minutes)
        inc = store.incidents.find_open(event.source_ip, event.started_at - window)
        created = inc is None
        if inc is None:
            inc = store.incidents.create(event.source_ip, event.started_at)
            result.new_incidents += 1

        mergeable = store.events.find_mergeable(
            inc.id,
            event.scenario,
            event.started_at - timedelta(seconds=self._cfg.dedupe_window_seconds),
        )
        if mergeable is not None:
            store.events.merge(mergeable, event, self._cfg.max_sample_lines)
            result.merged_alerts += 1
        else:
            store.events.add(inc.id, event, self._cfg.max_sample_lines)

        new_scenario = event.scenario not in inc.scenarios
        self._update(inc, event)

        label = self._allowlist.match(event.source_ip)
        if label is not None:
            result.allowlisted += 1
            inc.needs_triage = False
            store.incidents.save(inc)
            if created:
                self._record_allowlisted(inc, label)
            return None

        triaged = inc.last_triaged_scenarios or []
        banned = "ban" in event.crowdsec_decisions
        signal = (
            created
            or (new_scenario and event.scenario not in triaged)
            or (mergeable is None and not banned)
        )
        if signal:
            inc.needs_triage = True
        store.incidents.save(inc)
        return inc.id if inc.needs_triage else None

    @staticmethod
    def _update(inc: IncidentRow, event: Event) -> None:
        inc.first_seen = min(inc.first_seen, event.started_at)
        inc.last_seen = max(inc.last_seen, event.stopped_at, event.started_at)
        inc.event_count += event.event_count
        if event.scenario not in inc.scenarios:
            inc.scenarios = [*inc.scenarios, event.scenario]

    def _record_allowlisted(self, inc: IncidentRow, label: str) -> None:
        reason = f"allowlisted:{label}"
        verdict_id = self._store.verdicts.add(
            inc.id,
            VerdictRecord(
                verdict=Verdict.unknown(f"source is allow-listed ({label}); not triaged"),
                model=SKIP_MODEL,
                prompt_version=SKIP_MODEL,
                skipped_reason=reason,
            ),
        )
        self._store.audit.append(
            Actor.SYSTEM, "verdict", {"skipped": reason}, incident_id=inc.id, ref_id=verdict_id
        )
        log.info("incident_allowlisted", incident_id=inc.id, ip=inc.source_ip, label=label)
