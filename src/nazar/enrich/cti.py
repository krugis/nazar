"""CrowdSec CTI smoke lookups with cache and circuit breaker (LLD 06).

Endpoint and fields verified against ``pkg/cticlient`` in CrowdSec.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

import httpx

from nazar.core.clock import Clock
from nazar.core.errors import CtiError
from nazar.core.log import get_logger
from nazar.core.sanitize import clean_line
from nazar.models import Incident
from nazar.store import EventRow, Store

log = get_logger(__name__)

RATE_LIMIT_PAUSE = timedelta(minutes=5)
_MAX_ITEMS = 20
_SHORT = 80


def _names(items: Any, prefix: str = "") -> list[str]:
    if not isinstance(items, list):
        return []
    out = []
    for item in items[:_MAX_ITEMS]:
        if isinstance(item, dict) and item.get("name"):
            out.append(prefix + clean_line(item["name"], _SHORT))
    return out


def normalize(body: dict[str, Any]) -> dict[str, Any]:
    """Keep only the fields Nazar uses, sanitized: CTI is third-party data."""
    rep = body.get("reputation")
    location = body.get("location")
    location = location if isinstance(location, dict) else {}
    classes = body.get("classifications")
    classes = classes if isinstance(classes, dict) else {}
    as_num, as_name = body.get("as_num"), body.get("as_name")
    return {
        "reputation": clean_line(rep, 20) if rep else "unknown",
        "behaviors": _names(body.get("behaviors")),
        "classifications": _names(classes.get("classifications"))
        + _names(classes.get("false_positives"), prefix="fp:"),
        "country": clean_line(location["country"], 8) if location.get("country") else None,
        "asn": clean_line(f"AS{as_num} {as_name}", _SHORT) if as_num and as_name else None,
    }


class CtiProvider:
    name = "cti"

    def __init__(
        self,
        store: Store,
        http: httpx.AsyncClient,
        clock: Clock,
        api_key: str,
        cache_hours: int = 24,
    ) -> None:
        self._store = store
        self._http = http
        self._clock = clock
        self._key = api_key
        self._max_age = timedelta(hours=cache_hours)
        self._paused_until: datetime | None = None
        self.key_rejected = False

    async def lookup(self, ip: str) -> dict[str, Any] | None:
        cached = self._store.cti_cache.get(ip, self._max_age)
        if cached is not None:
            return cached
        now = self._clock.now()
        if self.key_rejected or (self._paused_until and now < self._paused_until):
            return None
        try:
            resp = await self._http.get(f"/smoke/{ip}", headers={"X-Api-Key": self._key})
        except httpx.HTTPError as exc:
            raise CtiError(f"CTI request failed: {type(exc).__name__}") from exc
        if resp.status_code == 404:
            body: dict[str, Any] = normalize({"reputation": "unknown"})
        elif resp.status_code == 429:
            self._paused_until = now + RATE_LIMIT_PAUSE
            log.warning("cti_rate_limited", paused_minutes=5)
            return None
        elif resp.status_code in (401, 403):
            self.key_rejected = True
            log.error("cti_key_rejected", status=resp.status_code)
            return None
        elif resp.status_code != 200:
            raise CtiError(f"CTI returned HTTP {resp.status_code}")
        else:
            try:
                raw = resp.json()
            except ValueError as exc:
                raise CtiError("CTI returned invalid JSON") from exc
            body = normalize(raw if isinstance(raw, dict) else {})
        self._store.cti_cache.put(ip, body)
        return body

    async def enrich(self, incident: Incident, events: Sequence[EventRow]) -> dict[str, Any]:
        body = await self.lookup(incident.source_ip)
        if body is None:
            return {}
        return {
            "cti_reputation": body.get("reputation"),
            "cti_behaviors": body.get("behaviors") or [],
            "cti_classifications": body.get("classifications") or [],
            "country": body.get("country"),
            "asn": body.get("asn"),
        }
