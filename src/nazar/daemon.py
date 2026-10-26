"""Long-running tasks: collect, triage, housekeeping (LLD 11)."""

from __future__ import annotations

import asyncio
import contextlib
import signal
from collections.abc import Awaitable, Callable
from datetime import timedelta
from zoneinfo import ZoneInfo

from nazar import __version__
from nazar.app import App
from nazar.core.clock import to_iso
from nazar.core.errors import LapiError, ModelUnavailableError, NotifierError
from nazar.core.log import get_logger
from nazar.notify import TextNote, build_summary, render_summary
from nazar.pipeline import PipelineResult, report_line
from nazar.prefilter import build_allowlist, crowdsec_cidrs
from nazar.store import IncidentRow

log = get_logger(__name__)

MAX_PIPELINE_FAILURES = 3
MAX_MODEL_RETRIES = 5
MODEL_RETRY_BASE_S = 10.0
HOUSEKEEPING_SECONDS = 60
SHUTDOWN_GRACE_S = 60.0
RETENTION_EVERY = timedelta(hours=24)
HEALTH_KEY = "health"
SUMMARY_KEY = "summary.last_sent"
ALLOWLIST_REFRESH_KEY = "allowlist.last_refresh"
ALLOWLIST_EVERY = timedelta(hours=1)

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
        await self.refresh_allowlists()
        await self.health_check()
        tasks = [
            asyncio.create_task(self._supervise("collect", self._collect_loop)),
            asyncio.create_task(self._supervise("housekeeping", self._housekeeping_loop)),
        ]
        if self.app.telegram is not None:
            tasks.append(asyncio.create_task(self._supervise("telegram", self._telegram_loop)))
        triage = asyncio.create_task(self._supervise("triage", self._triage_loop))
        await self._stop.wait()
        log.info("nazar_stopping")
        for task in tasks:
            task.cancel()
        # Let the incident in progress finish, but stay inside systemd's TimeoutStopSec (90 s);
        # an interrupted incident stays pending and is triaged after the restart.
        try:
            await asyncio.wait_for(triage, timeout=SHUTDOWN_GRACE_S)
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
        retry_key = f"pipeline.model_retries.{incident_id}"
        retries = int(app.store.kv.get(retry_key, 0))
        try:
            result = await app.pipeline.process(
                incident_id, retry_exhausted=retries >= MAX_MODEL_RETRIES
            )
        except ModelUnavailableError:
            # Keep the incident pending, put it back in the queue and back off, so one Ollama
            # outage does not turn the whole queue into "unknown" verdicts.
            app.store.kv.set(retry_key, retries + 1)
            row = app.store.incidents.get(incident_id)
            if row is not None:
                self._enqueue(row)
            delay = min(MODEL_RETRY_BASE_S * 2**retries, 300.0)
            log.warning("model_unavailable_retry_later", incident_id=incident_id,
                        attempt=retries + 1, retry_in=delay)  # fmt: skip
            await self._sleep(delay)
            return None
        except Exception:
            failures = int(app.store.kv.get(key, 0)) + 1
            app.store.kv.set(key, failures)
            log.error("incident_failed", incident_id=incident_id, failures=failures, exc_info=True)
            if failures >= MAX_PIPELINE_FAILURES:
                app.pipeline.record_skipped([incident_id], "pipeline_failed")
            return None
        if retries:
            app.store.kv.set(retry_key, 0)
        if result is not None and result.decision is not None and result.decision.unusual_volume:
            await app.health.update(
                "volume", "warning", "automatic action budget reached; actions need approval"
            )
        if result is not None and self._report and app.cfg.dry_run:
            self._report(report_line(result))
        return result

    async def refresh_allowlists(self) -> None:
        """Import CrowdSec allow-lists into Nazar's allow-list (``crowdsec.import_allowlists``)."""
        app = self.app
        if not app.cfg.crowdsec.import_allowlists:
            return
        try:
            lists = await app.lapi.get_allowlists()
        except LapiError as exc:
            log.warning("allowlist_import_failed", error=str(exc))
            return
        cidrs = crowdsec_cidrs(lists, app.clock.now())
        app.allowlist.replace(
            build_allowlist(app.cfg.policy, host_addresses=app.host_addresses, crowdsec_cidrs=cidrs)
        )
        app.store.kv.set(ALLOWLIST_REFRESH_KEY, to_iso(app.clock.now()))
        log.info("allowlist_imported", lists=len(lists), entries=len(cidrs))

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
        health = app.health
        await health.update("lapi", "up" if lapi_ok else "down", app.cfg.crowdsec.lapi_url)
        await health.update("ollama", "up" if backend.reachable else "down", backend.detail or "")
        if backend.reachable:
            await health.update(
                "model",
                "up" if backend.model_present else "down",
                "" if backend.model_present else f"{app.cfg.analyst.model} is not pulled",
            )
        await health.update(
            "model_output",
            "warning" if app.analyst.output_unhealthy else "up",
            f"{app.analyst.consecutive_invalid} invalid answers in a row",
        )
        if app.cti is not None:
            await health.update(
                "cti", "warning" if app.cti.key_rejected else "up", "CTI API key rejected"
            )
        since = app.clock.now() - timedelta(hours=1)
        if (
            app.store.decisions.count_auto_enforced(since)
            < app.cfg.policy.max_auto_actions_per_hour
        ):
            await health.update("volume", "up")
        return snapshot

    async def daily_summary_if_due(self) -> bool:
        app = self.app
        tz = ZoneInfo(app.cfg.notifier.timezone)
        local = app.clock.now().astimezone(tz)
        today = local.date().isoformat()
        last = app.store.kv.get(SUMMARY_KEY)
        due = local.strftime("%H:%M") >= app.cfg.notifier.daily_summary_time
        if last is None and due:
            # First start after today's summary time: begin tomorrow, not right away.
            app.store.kv.set(SUMMARY_KEY, today)
            return False
        if not due or last == today:
            return False
        now = app.clock.now()
        text = render_summary(build_summary(app.store, now - timedelta(hours=24), now))
        await app.notifier.send(TextNote(kind="daily_summary", title="Daily summary", text=text))
        app.store.kv.set(SUMMARY_KEY, today)
        return True

    # ------------------------------------------------------------------ internals

    def _enqueue(self, row: IncidentRow) -> None:
        events = self.app.store.events.for_incident(row.id)
        banned = any("ban" in e.crowdsec_decisions for e in events)
        evicted = self.app.queue.push(row, banned=banned)
        if evicted:
            self.app.pipeline.record_skipped(evicted, "rate_limited_bulk")
            log.warning("triage_queue_overflow", summarized=len(evicted))

    async def _telegram_loop(self) -> None:
        app = self.app
        assert app.telegram is not None
        failures = 0
        while not self._stop.is_set():
            try:
                actions = await app.telegram.poll_actions()
            except NotifierError as exc:
                failures += 1
                await app.health.update("telegram", "down", str(exc))
                await self._sleep(min(5 * 2 ** (failures - 1), 300))
                continue
            if failures:
                failures = 0
                await app.health.update("telegram", "up")
            for action in actions:
                await app.approvals.handle(action)

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
            await app.approvals.expire_due()
            await self.daily_summary_if_due()
            await self.health_check()
            refreshed = app.store.kv.get(ALLOWLIST_REFRESH_KEY)
            if refreshed is None or refreshed < to_iso(app.clock.now() - ALLOWLIST_EVERY):
                await self.refresh_allowlists()
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
