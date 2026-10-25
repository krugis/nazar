"""Composition root: builds every service once (LLD 11). Daemon, CLI and tests use it."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

from nazar import __version__
from nazar.actuator import (
    Actuator,
    CscliDecisionBackend,
    DecisionBackend,
    FallbackDecisionBackend,
    LapiDecisionBackend,
)
from nazar.analyst import Analyst, LlmBackend, OllamaBackend, PromptTemplate
from nazar.collector import LapiAlertSource, LapiClient
from nazar.config import Config, secret
from nazar.core.clock import Clock, SystemClock
from nazar.enrich import (
    AlertGeoProvider,
    CtiProvider,
    Enricher,
    EnrichmentProvider,
    GeoIpProvider,
    HistoryProvider,
)
from nazar.pipeline import Pipeline
from nazar.prefilter import Grouper, RefreshableAllowList, TriageQueue, build_allowlist
from nazar.store import Store

USER_AGENT = f"nazar/{__version__}"


@dataclass
class App:
    cfg: Config
    clock: Clock
    store: Store
    lapi: LapiClient
    source: LapiAlertSource
    allowlist: RefreshableAllowList
    grouper: Grouper
    queue: TriageQueue
    enricher: Enricher
    backend: LlmBackend
    analyst: Analyst
    pipeline: Pipeline
    actuator: Actuator
    host_addresses: list[str] | None = None
    """Fixed host addresses (tests); None means discover them from the system."""
    _clients: tuple[httpx.AsyncClient, ...] = ()

    async def aclose(self) -> None:
        for client in self._clients:
            await client.aclose()
        self.store.close()


def build_app(
    cfg: Config,
    *,
    clock: Clock | None = None,
    store_path: Path | str | None = None,
    lapi_http: httpx.AsyncClient | None = None,
    ollama_http: httpx.AsyncClient | None = None,
    backend: LlmBackend | None = None,
    host_addresses: list[str] | None = None,
    prompt_path: Path | None = None,
    cti_http: httpx.AsyncClient | None = None,
    decision_backend: DecisionBackend | None = None,
) -> App:
    clock = clock or SystemClock()
    headers = {"User-Agent": USER_AGENT}
    owned: list[httpx.AsyncClient] = []
    if lapi_http is None:
        lapi_http = httpx.AsyncClient(
            base_url=cfg.crowdsec.lapi_url, timeout=cfg.crowdsec.timeout_seconds, headers=headers
        )
        owned.append(lapi_http)
    if backend is None:
        if ollama_http is None:
            ollama_http = httpx.AsyncClient(
                base_url=cfg.analyst.ollama_url,
                timeout=cfg.analyst.timeout_seconds,
                headers=headers,
            )
            owned.append(ollama_http)
        backend = OllamaBackend(cfg.analyst, ollama_http)

    store = Store(store_path or cfg.store.path, clock)
    lapi = LapiClient(
        cfg.crowdsec.machine_id, secret(cfg.crowdsec.password_env) or "", lapi_http, clock
    )
    allowlist = RefreshableAllowList(build_allowlist(cfg.policy, host_addresses=host_addresses))

    # Provider order is trust order: the first non-null value of a field wins (LLD 06).
    providers: list[EnrichmentProvider] = [AlertGeoProvider()]
    geoip = GeoIpProvider.from_paths(cfg.enrich.geoip_country_db, cfg.enrich.geoip_asn_db)
    if geoip is not None:
        providers.append(geoip)
    cti_key = secret(cfg.crowdsec.cti_api_key_env)
    if cti_key:
        if cti_http is None:
            cti_http = httpx.AsyncClient(
                base_url=cfg.crowdsec.cti_url, timeout=cfg.enrich.timeout_seconds, headers=headers
            )
            owned.append(cti_http)
        providers.append(CtiProvider(store, cti_http, clock, cti_key, cfg.crowdsec.cti_cache_hours))
    providers.append(HistoryProvider(store))
    enricher = Enricher(providers, timeout_s=cfg.enrich.timeout_seconds)

    if decision_backend is None:
        decision_backend = LapiDecisionBackend(lapi, clock, cfg.crowdsec.decision_origin)
        if cfg.crowdsec.use_cscli_fallback:
            decision_backend = FallbackDecisionBackend(decision_backend, CscliDecisionBackend())
    actuator = Actuator(cfg, store, decision_backend, allowlist, clock)
    analyst = Analyst(backend, PromptTemplate.load(prompt_path))
    return App(
        cfg=cfg,
        clock=clock,
        store=store,
        lapi=lapi,
        source=LapiAlertSource(lapi, store, clock, cfg.collector, cfg.prefilter),
        allowlist=allowlist,
        grouper=Grouper(store, allowlist, cfg.prefilter),
        queue=TriageQueue(clock, cfg.analyst.max_calls_per_minute, cfg.analyst.max_queue),
        enricher=enricher,
        backend=backend,
        analyst=analyst,
        pipeline=Pipeline(cfg, store, clock, allowlist, enricher, analyst, actuator),
        actuator=actuator,
        host_addresses=host_addresses,
        _clients=tuple(owned),
    )
