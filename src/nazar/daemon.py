"""Long-running tasks: collect, triage, housekeeping (LLD 11)."""

from __future__ import annotations

import asyncio
import contextlib
import signal
from collections.abc import Awaitable, Callable
from datetime import timedelta

from nazar import __version__
from nazar.app import App
from nazar.core.clock import to_iso
from nazar.core.errors import LapiError
from nazar.core.log import get_logger
from nazar.models import Actor
from nazar.pipeline import PipelineResult, report_line
from nazar.store import IncidentRow

log = get_logger(__name__)

MAX_PIPELINE_FAILURES = 3
HOUSEKEEPING_SECONDS = 60
RETENTION_EVERY = timedelta(hours=24)
HEALTH_KEY = "health"

Reporter = Callable[[str], None]


class Daemon:
    def __init__(self, app: App, *, reporter: Reporter | None = None) -> None:
        self.app = app
        self._report = reporter
        self._stop = asyncio.Event()
        self._lapi_failures = 0

    # ------------------------------------------------------------------ public

    def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        cfg = self.app.cfg
        log.info(
            "nazar_started",
            version=__version__,
            mode=cfg.mode.value,
            model=cfg.analyst.model,
            prompt_version=self.app.analyst.template.version,
        )
        self._install_signals()
        if not cfg.dry_run:
            try:
                reconciled = await self.app.actuator.reconcile()
                if reconciled:
                    log.warning("decisions_reconciled", count=reconciled)
            except LapiError as exc:
                log.warning("reconcile_failed", error=str(exc))
        self.restore_queue()
        await self.health_check()
        tasks = [
            asyncio.create_task(self._supervise("collect", self._collect_loop)),
            asyncio.create_task(self._supervise("housekeeping", self._housekeeping_loop)),
        ]
        triage = asyncio.create_task(self._supervise("triage", self._triage_loop))
        await self._stop.wait()
        log.info("nazar_stopping")
        for task in tasks:
            task.cancel()
        # Let the incident in progress finish, bounded by the model timeout.
        try:
            await asyncio.wait_for(triage, timeout=cfg.analyst.timeout_seconds * 2 + 5)
        except TimeoutError:
            triage.cancel()
        await asyncio.gather(*tasks, triage, return_exceptions=True)
        log.info("nazar_stopped")

    async def run_once(self) -> list[PipelineResult]:
        """One collect cycle, then triage until the queue is empty (``run --once``)."""
        self.restore_queue()
        await self.collect_once()
        results: list[PipelineResult] = []
        while len(self.app.queue):
            incident_id = await self.app.queue.next()
            result = await self.process(incident_id)
            if result is not None:
                results.append(result)
        return results

    def restore_queue(self) -> None:
        for row in self.app.store.incidents.pending_triage(limit=self.app.cfg.analyst.max_queue):
            self._enqueue(row)

    async def collect_once(self) -> int:
        """Poll the LAPI, store events, enqueue incidents. Returns the number of new events."""
        app = self.app
        result = await app.source.poll()
        with app.store.transaction():
            ingest = app.grouper.ingest(result.events)
            app.source.commit(result)
        for incident_id in ingest.needs_triage:
            row = app.store.incidents.get(incident_id)
            if row is not None:
                self._enqueue(row)
        if result.events:
            log.info(
                "alerts_collected",
                events=len(result.events),
                ignored=result.ignored,
                new_incidents=ingest.new_incidents,
                merged=ingest.merged_alerts,
                allowlisted=ingest.allowlisted,
                queued=len(app.queue),
            )
        return len(result.events)

    async def process(self, incident_id: str) -> PipelineResult | None:
        """Run the pipeline for one incident; failures are contained and counted."""
        app = self.app
        key = f"pipeline.failures.{incident_id}"
        try:
            result = await app.pipeline.process(incident_id)
        except Exception:
            failures = int(app.store.kv.get(key, 0)) + 1
            app.store.kv.set(key, failures)
            log.error("incident_failed", incident_id=incident_id, failures=failures, exc_info=True)
            if failures >= MAX_PIPELINE_FAILURES:
                app.pipeline.record_skipped([incident_id], "pipeline_failed")
            return None
        if result is not None and self._report and app.cfg.dry_run:
            self._report(report_line(result))
        return result

    async def health_check(self) -> dict[str, object]:
        app = self.app
        lapi_ok = await app.lapi.health()
        backend = await app.backend.health()
        snapshot: dict[str, object] = {
            "updated_at": to_iso(app.clock.now()),
            "lapi": lapi_ok,
            "ollama": backend.reachable,
            "model_present": backend.model_present,
            "ollama_version": backend.version,
            "model_output_ok": not app.analyst.output_unhealthy,
            "queue": len(app.queue),
            "mode": app.cfg.mode.value,
        }
        app.store.kv.set(HEALTH_KEY, snapshot)
        if not lapi_ok:
            log.warning("health_lapi_down")
        if not backend.reachable:
            log.warning("health_ollama_down")
        elif not backend.model_present:
            log.warning("health_model_missing", model=app.cfg.analyst.model)
        if app.analyst.output_unhealthy:
            log.warning("health_model_output_invalid", consecutive=app.analyst.consecutive_invalid)
        return snapshot

    # ------------------------------------------------------------------ internals

    def _enqueue(self, row: IncidentRow) -> None:
        events = self.app.store.events.for_incident(row.id)
        banned = any("ban" in e.crowdsec_decisions for e in events)
        evicted = self.app.queue.push(row, banned=banned)
        if evicted:
            self.app.pipeline.record_skipped(evicted, "rate_limited_bulk")
            log.warning("triage_queue_overflow", summarized=len(evicted))

    async def _collect_loop(self) -> None:
        interval = self.app.cfg.collector.interval_seconds
        while not self._stop.is_set():
            try:
                await self.collect_once()
                self._lapi_failures = 0
                delay: float = interval
            except LapiError as exc:
                self._lapi_failures += 1
                delay = min(5 * 2 ** (self._lapi_failures - 1), 300)
                log.warning(
                    "collect_failed", error=str(exc), failures=self._lapi_failures, retry_in=delay
                )
            await self._sleep(delay)

    async def _triage_loop(self) -> None:
        while not self._stop.is_set():
            next_item = asyncio.create_task(self.app.queue.next())
            stopper = asyncio.create_task(self._stop.wait())
            done, _ = await asyncio.wait({next_item, stopper}, return_when=asyncio.FIRST_COMPLETED)
            stopper.cancel()
            if next_item not in done:
                next_item.cancel()
                return
            await self.process(next_item.result())

    async def _housekeeping_loop(self) -> None:
        app = self.app
        while not self._stop.is_set():
            window = timedelta(minutes=app.cfg.prefilter.incident_window_minutes)
            app.store.incidents.close_stale(app.clock.now() - window)
            for approval in app.store.approvals.expire_due():
                app.store.audit.append(
                    Actor.SYSTEM,
                    "approval",
                    {"status": "expired"},
                    incident_id=approval.incident_id,
                    ref_id=approval.approval_id,
                )
                log.info("approval_expired", approval_id=approval.approval_id)
            await self.health_check()
            last = app.store.kv.get("retention.last_run")
            if last is None or last < to_iso(app.clock.now() - RETENTION_EVERY):
                removed = app.store.purge(
                    timedelta(days=app.cfg.store.retention_days),
                    app.cfg.policy.max_ban,
                    timedelta(hours=app.cfg.crowdsec.cti_cache_hours),
                )
                app.store.kv.set("retention.last_run", to_iso(app.clock.now()))
                log.info("retention_done", incidents_removed=removed)
            await self._sleep(HOUSEKEEPING_SECONDS)

    async def _sleep(self, seconds: float) -> None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._stop.wait(), timeout=seconds)

    async def _supervise(self, name: str, loop: Callable[[], Awaitable[None]]) -> None:
        """Restart a task loop after an unexpected error; it never stops the daemon."""
        backoff = 5.0
        while not self._stop.is_set():
            try:
                await loop()
                return
            except asyncio.CancelledError:
                raise
            except Exception:
                log.error("task_crashed", task=name, restart_in=backoff, exc_info=True)
                await self._sleep(backoff)
                backoff = min(backoff * 2, 300)

    def _install_signals(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.add_signal_handler(sig, self.stop)
