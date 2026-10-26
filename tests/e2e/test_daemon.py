"""LAPI fixtures → incidents → fake model → policy, through the real App and Daemon."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from nazar.app import App, build_app
from nazar.config import Config, Mode, PolicyConfig
from nazar.core.clock import FrozenClock
from nazar.daemon import Daemon
from nazar.models import Outcome, VerdictLabel
from tests.analyst.conftest import FakeBackend
from tests.conftest import FIXTURES

LAPI = "http://lapi.test"
VALID = (FIXTURES / "model_outputs" / "valid_clean.txt").read_text()


def _alerts() -> list[dict[str, Any]]:
    return json.loads((FIXTURES / "lapi" / "alerts.json").read_text())


@pytest.fixture
def lapi_mock() -> respx.MockRouter:
    with respx.mock(base_url=LAPI, assert_all_called=False) as router:
        router.post("/v1/watchers/login").mock(
            return_value=httpx.Response(200, json={"token": "t", "expire": "2026-10-26T00:00:00Z"})
        )
        router.get("/v1/alerts").mock(return_value=httpx.Response(200, json=_alerts()))
        yield router


@pytest.fixture
async def make_app(tmp_path: Path, clock: FrozenClock) -> AsyncIterator[Any]:
    apps: list[App] = []

    def factory(backend: FakeBackend, cfg: Config | None = None) -> App:
        http = httpx.AsyncClient(base_url=LAPI)
        app = build_app(
            cfg or Config(),
            clock=clock,
            store_path=tmp_path / "nazar.db",
            lapi_http=http,
            backend=backend,
            host_addresses=[],
        )
        app._clients = (http,)
        apps.append(app)
        return app

    yield factory
    for app in apps:
        await app.aclose()


async def test_run_once_dry_run(lapi_mock: respx.MockRouter, make_app: Any) -> None:
    backend = FakeBackend(VALID, VALID)
    app = make_app(backend)
    lines: list[str] = []
    results = await Daemon(app, reporter=lines.append).run_once()
    ips = sorted(r.incident.source_ip for r in results)
    assert ips == ["198.51.100.7", "203.0.113.45"]
    intended = {}
    for r in results:
        assert r.verdict.verdict is VerdictLabel.MALICIOUS
        assert r.decision is not None and r.decision.outcome is Outcome.REPORT_ONLY  # dry-run
        intended[r.incident.source_ip] = r.decision.intended_outcome
    # R8: one scenario and no CTI/history → approval; R5: CrowdSec already bans → report only.
    assert intended == {"198.51.100.7": Outcome.APPROVAL, "203.0.113.45": Outcome.REPORT_ONLY}
    assert len(lines) == 2 and "would=approval" in lines[0]
    # No call ever writes to CrowdSec in M1.
    assert not [
        c
        for c in lapi_mock.calls
        if c.request.method in ("POST", "DELETE") and c.request.url.path != "/v1/watchers/login"
    ]
    # The model saw the injected user agent only as escaped data.
    prompt = backend.calls[0][1]["content"] + backend.calls[1][1]["content"]
    assert prompt.count("</data>") == 2
    # Second cycle: nothing new.
    assert await Daemon(app).run_once() == []


async def test_allowlisted_never_reaches_model(lapi_mock: respx.MockRouter, make_app: Any) -> None:
    backend = FakeBackend(VALID)
    cfg = Config(policy=PolicyConfig(allowlist_cidrs=["198.51.100.0/24"]))
    app = make_app(backend, cfg)
    results = await Daemon(app).run_once()
    assert [r.incident.source_ip for r in results] == ["203.0.113.45"]
    assert len(backend.calls) == 1
    allowed = app.store.incidents.list(app.clock.now().replace(year=2020), "198.51.100.7")
    verdicts = app.store.verdicts.for_incident(allowed[0].id)
    assert verdicts[0].record.skipped_reason == "allowlisted:config"


async def test_model_failure_is_contained(lapi_mock: respx.MockRouter, make_app: Any) -> None:
    app = make_app(FakeBackend("garbage", "garbage", VALID))
    results = await Daemon(app).run_once()
    # Not banned by CrowdSec → higher priority → triaged first, and gets the garbage.
    by_ip = {r.incident.source_ip: r for r in results}
    assert by_ip["198.51.100.7"].verdict.verdict is VerdictLabel.UNKNOWN
    assert not by_ip["198.51.100.7"].valid_output
    assert by_ip["203.0.113.45"].verdict.verdict is VerdictLabel.MALICIOUS


async def test_pipeline_exception_retried_then_recorded(
    lapi_mock: respx.MockRouter, make_app: Any
) -> None:
    class Exploding(FakeBackend):
        async def chat(self, messages: Any, schema: Any) -> Any:
            raise RuntimeError("unexpected bug")

    app = make_app(Exploding())
    daemon = Daemon(app)
    await daemon.collect_once()
    incident_id = app.store.incidents.pending_triage()[0].id
    for _ in range(3):
        assert await daemon.process(incident_id) is None
    rows = app.store.verdicts.for_incident(incident_id)
    assert rows[-1].record.skipped_reason == "pipeline_failed"


async def test_skip_trivial_when_already_banned(lapi_mock: respx.MockRouter, make_app: Any) -> None:
    backend = FakeBackend(VALID, VALID)
    app = make_app(backend)
    daemon = Daemon(app)
    await daemon.run_once()
    banned = next(
        i
        for i in app.store.incidents.list(app.clock.now().replace(year=2020))
        if i.source_ip == "203.0.113.45"
    )
    # Re-flag for triage with no new scenario: CrowdSec bans already, so the model is skipped.
    banned.needs_triage = True
    app.store.incidents.save(banned)
    result = await app.pipeline.process(banned.id)
    assert result is not None and result.skipped_reason == "already_banned_no_new_signal"
    assert len(backend.calls) == 2


async def test_audit_trail(lapi_mock: respx.MockRouter, make_app: Any) -> None:
    app = make_app(FakeBackend(VALID, VALID), Config(mode=Mode.DRY_RUN))
    results = await Daemon(app).run_once()
    trail = app.store.audit.for_incident(results[0].incident.incident_id)
    assert [e["kind"] for e in trail] == ["verdict", "decision"]
    assert trail[0]["actor"] == "model" and trail[1]["actor"] == "policy"
    assert trail[0]["detail"]["prompt_version"] == "triage-v1"


async def test_model_outage_requeues_instead_of_unknown(
    lapi_mock: respx.MockRouter, make_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An Ollama outage must not turn queued incidents into unknown verdicts."""
    from nazar import daemon as daemon_mod
    from nazar.core.errors import LlmError

    monkeypatch.setattr(daemon_mod, "MODEL_RETRY_BASE_S", 0.0)
    backend = FakeBackend(LlmError("down"), LlmError("down"), VALID, VALID)
    app = make_app(backend)
    results = await Daemon(app).run_once()
    assert len(results) == 2
    assert all(r.verdict.verdict is VerdictLabel.MALICIOUS for r in results)
    # no placeholder verdicts were stored for the failed attempts
    for r in results:
        rows = app.store.verdicts.for_incident(r.incident.incident_id)
        assert [v.record.verdict.verdict for v in rows] == [VerdictLabel.MALICIOUS]


async def test_model_outage_gives_up_after_max_retries(
    lapi_mock: respx.MockRouter, make_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nazar import daemon as daemon_mod
    from nazar.core.errors import LlmError

    monkeypatch.setattr(daemon_mod, "MODEL_RETRY_BASE_S", 0.0)
    attempts = (daemon_mod.MAX_MODEL_RETRIES + 1) * 2
    app = make_app(FakeBackend(*[LlmError("down")] * attempts))
    results = await Daemon(app).run_once()
    assert len(results) == 2
    assert all(r.verdict.verdict is VerdictLabel.UNKNOWN for r in results)
    assert all(not r.valid_output for r in results)
