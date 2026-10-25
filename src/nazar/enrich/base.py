"""Enrichment framework: providers run concurrently, failures never block triage (LLD 06)."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any, Protocol

from nazar.core.log import get_logger
from nazar.models import Enrichment, History, Incident
from nazar.store import EventRow

log = get_logger(__name__)

_LIST_FIELDS = ("cti_behaviors", "cti_classifications")


class EnrichmentProvider(Protocol):
    name: str

    async def enrich(self, incident: Incident, events: Sequence[EventRow]) -> dict[str, Any]:
        """Return the ``Enrichment`` fields this provider knows. Unknown keys are ignored."""
        ...


class Enricher:
    """Runs providers in order of trust: for scalar fields the first non-null value wins."""

    def __init__(self, providers: Sequence[EnrichmentProvider], timeout_s: float = 5.0) -> None:
        self.providers = list(providers)
        self._timeout = timeout_s

    async def _run(
        self, provider: EnrichmentProvider, incident: Incident, events: Sequence[EventRow]
    ) -> dict[str, Any]:
        try:
            return await asyncio.wait_for(provider.enrich(incident, events), self._timeout)
        except Exception as exc:  # a provider must never break triage
            log.warning(
                "enrichment_failed",
                provider=provider.name,
                incident_id=incident.incident_id,
                error=type(exc).__name__,
            )
            return {}

    async def enrich(self, incident: Incident, events: Sequence[EventRow]) -> Enrichment:
        results = await asyncio.gather(*(self._run(p, incident, events) for p in self.providers))
        merged: dict[str, Any] = {}
        for result in results:
            for key, value in result.items():
                if key not in Enrichment.model_fields or value is None:
                    continue
                if key in _LIST_FIELDS:
                    current = merged.setdefault(key, [])
                    current.extend(v for v in value if v not in current)
                else:
                    merged.setdefault(key, value)
        if isinstance(merged.get("history"), dict):
            merged["history"] = History.model_validate(merged["history"])
        return Enrichment.model_validate(merged)
