"""Composition root: builds every service once (LLD 11). Daemon, CLI and tests use it."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

from nazar import __version__
from nazar.analyst import Analyst, LlmBackend, OllamaBackend, PromptTemplate
from nazar.collector import LapiAlertSource, LapiClient
from nazar.config import Config, secret
from nazar.core.clock import Clock, SystemClock
from nazar.enrich import AlertGeoProvider, Enricher, HistoryProvider
from nazar.pipeline import Pipeline
from nazar.prefilter import AllowList, Grouper, TriageQueue, build_allowlist
from nazar.store import Store

USER_AGENT = f"nazar/{__version__}"


@dataclass
class App:
    cfg: Config
    clock: Clock
    store: Store
    lapi: LapiClient
    source: LapiAlertSource
    allowlist: AllowList
    grouper: Grouper
    queue: TriageQueue
    enricher: Enricher
    backend: LlmBackend
    analyst: Analyst
    pipeline: Pipeline
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
    allowlist = build_allowlist(cfg.policy, host_addresses=host_addresses)
    enricher = Enricher([AlertGeoProvider(), HistoryProvider(store)])
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
        pipeline=Pipeline(cfg, store, clock, allowlist, enricher, analyst),
        _clients=tuple(owned),
    )
