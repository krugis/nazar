"""Previous incidents and bans for the IP, from the store (LLD 06)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from nazar.models import Incident
from nazar.store import EventRow, Store


class HistoryProvider:
    name = "history"

    def __init__(self, store: Store) -> None:
        self._store = store

    async def enrich(self, incident: Incident, events: Sequence[EventRow]) -> dict[str, Any]:
        ip, iid = incident.source_ip, incident.incident_id
        previous = self._store.incidents.count_for_ip(ip, exclude_id=iid)
        nazar_bans = [
            d
            for d in self._store.decisions.applied(source_ip=ip, active_only=False)
            if d.incident_id != iid
        ]
        row = self._store.db.one(
            "SELECT COUNT(DISTINCT e.incident_id) FROM events e JOIN incidents i"
            " ON i.id = e.incident_id WHERE i.source_ip = ? AND i.id != ?"
            " AND e.crowdsec_decisions LIKE '%\"ban\"%'",
            (ip, iid),
        )
        crowdsec_bans = int(row[0]) if row else 0
        return {
            "history": {
                "previous_incidents": previous,
                "previous_bans": len(nazar_bans) + crowdsec_bans,
            }
        }
