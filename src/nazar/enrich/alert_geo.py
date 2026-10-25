"""Country and ASN from CrowdSec's own alert data (LLD 06). No I/O."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from nazar.models import Incident
from nazar.store import EventRow


class AlertGeoProvider:
    name = "alert_geo"

    async def enrich(self, incident: Incident, events: Sequence[EventRow]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for event in sorted(events, key=lambda e: e.last_ts, reverse=True):
            if "country" not in result and event.country:
                result["country"] = event.country
            if "asn" not in result and event.asn:
                result["asn"] = event.asn
        return result
