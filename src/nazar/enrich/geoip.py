"""Optional MaxMind GeoLite2 lookups (LLD 06). Needs the ``geoip`` extra and database files."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from nazar.core.log import get_logger
from nazar.core.sanitize import clean_line
from nazar.models import Incident
from nazar.store import EventRow

log = get_logger(__name__)

Lookup = Callable[[str], dict[str, Any]]


def _open_reader(path: Path) -> Any:
    import geoip2.database  # optional dependency

    return geoip2.database.Reader(str(path))


class GeoIpProvider:
    name = "geoip"

    def __init__(self, country: Lookup | None, asn: Lookup | None) -> None:
        self._country = country
        self._asn = asn

    @classmethod
    def from_paths(cls, country_db: Path | None, asn_db: Path | None) -> GeoIpProvider | None:
        """Build from database paths, or None when GeoIP is not usable (logged at info)."""
        if not country_db and not asn_db:
            return None
        try:
            country_reader = _open_reader(country_db) if country_db else None
            asn_reader = _open_reader(asn_db) if asn_db else None
        except ImportError:
            log.info("geoip_disabled", reason="geoip2 not installed (pip install nazar-sec[geoip])")
            return None
        except (OSError, ValueError) as exc:
            log.info("geoip_disabled", reason=type(exc).__name__)
            return None

        def country(ip: str) -> dict[str, Any]:
            assert country_reader is not None
            code = country_reader.country(ip).country.iso_code
            return {"country": code}

        def asn(ip: str) -> dict[str, Any]:
            assert asn_reader is not None
            rec = asn_reader.asn(ip)
            num, org = rec.autonomous_system_number, rec.autonomous_system_organization
            return {"asn": f"AS{num} {org}" if num and org else None}

        return cls(country if country_reader else None, asn if asn_reader else None)

    async def enrich(self, incident: Incident, events: Sequence[EventRow]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for lookup in (self._country, self._asn):
            if lookup is None:
                continue
            try:
                part = await asyncio.to_thread(lookup, incident.source_ip)
            except Exception as exc:  # address not in the database, corrupt record, ...
                log.debug("geoip_lookup_failed", error=type(exc).__name__)
                continue
            result.update({k: clean_line(v, 80) for k, v in part.items() if v})
        return result
