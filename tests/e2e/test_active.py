"""Active mode end to end: LAPI alerts → triage → policy → CrowdSec decisions (M2)."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from nazar.actuator import ApplyStatus
from nazar.app import App, build_app
from nazar.config import Config, CrowdSecConfig, Mode, PolicyConfig
from nazar.core.clock import FrozenClock
from nazar.daemon import Daemon
from nazar.models import Outcome
from tests.analyst.conftest import FakeBackend
from tests.conftest import FIXTURES

LAPI = "http://lapi.test"
CTI = "http://cti.test/v2"
VALID = (FIXTURES / "model_outputs" / "valid_clean.txt").read_text()
SMOKE = json.loads((FIXTURES / "cti" / "smoke_malicious.json").read_text())


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    alerts = json.loads((FIXTURES / "lapi" / "alerts.json").read_text())
    with respx.mock(assert_all_called=False) as r:
        r.post(f"{LAPI}/v1/watchers/login").mock(
            return_value=httpx.Response(200, json={"token": "t", "expire": "2099-01-01T00:00:00Z"})
        )
        r.get(f"{LAPI}/v1/alerts").mock(return_value=httpx.Response(200, json=alerts))
        r.post(f"{LAPI}/v1/alerts").mock(return_value=httpx.Response(201, json=["900"]))
        r.get(url__regex=rf"{CTI}/smoke/.*").mock(return_value=httpx.Response(200, json=SMOKE))
        yield r


@pytest.fixture
async def make_app(
    tmp_path: Path, clock: FrozenClock, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Any]:
    apps: list[App] = []

    def factory(cfg: Config, cti: bool = True) -> App:
        if cti:
            monkeypatch.setenv("NAZAR_CTI_KEY", "key")
        lapi_http = httpx.AsyncClient(base_url=LAPI)
        cti_http = httpx.AsyncClient(base_url=CTI)
        app = build_app(
            cfg,
            clock=clock,
            store_path=tmp_path / "nazar.db",
            lapi_http=lapi_http,
            cti_http=cti_http,
            backend=FakeBackend(VALID, VALID),
            host_addresses=[],
        )
        app._clients = (lapi_http, cti_http)
        apps.append(app)
        return app

    yield factory
    for app in apps:
        await app.aclose()


def _active(**policy: Any) -> Config:
    return Config(
        mode=Mode.ACTIVE,
        crowdsec=CrowdSecConfig(cti_api_key_env="NAZAR_CTI_KEY"),
        policy=PolicyConfig(**policy),
    )


def _pushed(router: respx.MockRouter) -> list[dict[str, Any]]:
    return [
        json.loads(c.request.content)[0]
        for c in router.calls
        if c.request.method == "POST" and c.request.url.path == "/v1/alerts"
    ]


async def test_auto_ban_through_lapi(router: respx.MockRouter, make_app: Any) -> None:
    app = make_app(_active())
    results = {r.incident.source_ip: r for r in await Daemon(app).run_once()}
    probe = results["198.51.100.7"]
    assert probe.decision is not None and probe.decision.outcome is Outcome.AUTO
    assert probe.applied is not None and probe.applied.status is ApplyStatus.APPLIED
    assert results["203.0.113.45"].decision.outcome is Outcome.REPORT_ONLY  # type: ignore[union-attr]
    pushed = _pushed(router)
    assert len(pushed) == 1
    assert pushed[0]["scenario"] == "nazar/ai-triage"
    assert pushed[0]["decisions"][0] == {"type": "ban", "scope": "Ip", "value": "198.51.100.7",
                                         "duration": "4h", "origin": "cscli",
                                         "scenario": "nazar/ai-triage"}  # fmt: skip
    assert probe.incident.enrichment.cti_reputation == "malicious"


async def test_approval_without_corroboration(router: respx.MockRouter, make_app: Any) -> None:
    app = make_app(_active(), cti=False)
    results = {r.incident.source_ip: r for r in await Daemon(app).run_once()}
    probe = results["198.51.100.7"]
    assert probe.decision.outcome is Outcome.APPROVAL  # type: ignore[union-attr]
    assert probe.approval_id and app.store.approvals.get(probe.approval_id)
    assert _pushed(router) == []
    app.clock.advance(minutes=61)  # type: ignore[attr-defined]
    assert [a.approval_id for a in app.store.approvals.expire_due()] == [probe.approval_id]


async def test_allowlisted_never_banned_in_active_mode(
    router: respx.MockRouter, make_app: Any
) -> None:
    app = make_app(_active(allowlist_cidrs=["198.51.100.0/24"]))
    await Daemon(app).run_once()
    assert _pushed(router) == []


async def test_budget_exhaustion_goes_to_approval(router: respx.MockRouter, make_app: Any) -> None:
    app = make_app(_active(max_auto_actions_per_hour=0))
    results = {r.incident.source_ip: r for r in await Daemon(app).run_once()}
    d = results["198.51.100.7"].decision
    assert d is not None and d.outcome is Outcome.APPROVAL and d.unusual_volume
    assert _pushed(router) == []
