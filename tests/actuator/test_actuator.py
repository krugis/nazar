from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import httpx
import pytest
import respx

from nazar.actuator import (
    CSCLI_REF,
    Actuator,
    ApplyStatus,
    BanRequest,
    CscliDecisionBackend,
    FallbackDecisionBackend,
    LapiDecisionBackend,
    idempotency_key,
)
from nazar.collector import LapiClient
from nazar.config import Config, Mode, PolicyConfig
from nazar.core.clock import FrozenClock
from nazar.core.errors import LapiError
from nazar.models import Action, Decision, Outcome, Verdict
from nazar.prefilter import build_allowlist
from nazar.store import Store, VerdictRecord

BASE = "http://lapi.test"
IP = "203.0.113.45"
ACTIVE = Config(mode=Mode.ACTIVE)


def _decision(
    store: Store,
    clock: FrozenClock,
    ip: str = IP,
    outcome: Outcome = Outcome.AUTO,
    action: Action = Action.BAN,
    incident_id: str | None = None,
) -> int:
    if incident_id is None:
        incident_id = store.incidents.create(ip, clock.now()).id
    vid = store.verdicts.add(incident_id, VerdictRecord(Verdict.unknown("x"), "m", "v"))
    d = Decision(action=action, outcome=outcome, intended_outcome=outcome, duration="4h")
    return store.decisions.add(incident_id, vid, d)


@pytest.fixture
async def lapi(clock: FrozenClock) -> AsyncIterator[LapiClient]:
    async with httpx.AsyncClient(base_url=BASE) as http:
        yield LapiClient("nazar", "pw", http, clock)


@pytest.fixture
def router() -> Any:
    with respx.mock(base_url=BASE, assert_all_called=False) as r:
        r.post("/v1/watchers/login").mock(
            return_value=httpx.Response(200, json={"token": "t", "expire": "2099-01-01T00:00:00Z"})
        )
        r.get("/v1/alerts").mock(return_value=httpx.Response(200, json=[]))
        r.post("/v1/alerts").mock(return_value=httpx.Response(201, json=["77"]))
        yield r


def _actuator(
    store: Store, clock: FrozenClock, lapi: LapiClient, cfg: Config = ACTIVE, backend: Any = None
) -> Actuator:
    allow = build_allowlist(cfg.policy, host_addresses=[])
    return Actuator(cfg, store, backend or LapiDecisionBackend(lapi, clock), allow, clock)


def _pushes(router: Any) -> list[Any]:
    return [
        c for c in router.calls if c.request.method == "POST" and c.request.url.path == "/v1/alerts"
    ]


def test_payload_snapshot(clock: FrozenClock) -> None:
    backend = LapiDecisionBackend(None, clock, origin="cscli")  # type: ignore[arg-type]
    req = BanRequest(IP, Action.BAN, "4h", "inc_2026_10_25_0001", 42)
    assert backend.payload(req) == [{
        "scenario": "nazar/ai-triage", "scenario_hash": "", "scenario_version": "",
        "message": "nazar inc_2026_10_25_0001 decision 42: ban 203.0.113.45 for 4h",
        "events_count": 1, "start_at": "2026-10-25T17:00:00Z", "stop_at": "2026-10-25T17:00:00Z",
        "capacity": 0, "leakspeed": "0", "simulated": False, "remediation": True, "events": [],
        "labels": ["nazar", "incident:inc_2026_10_25_0001"],
        "source": {"scope": "Ip", "value": IP, "ip": IP},
        "decisions": [{"type": "ban", "scope": "Ip", "value": IP, "duration": "4h",
                       "origin": "cscli", "scenario": "nazar/ai-triage"}],
    }]  # fmt: skip


async def test_apply_and_idempotency(
    store: Store, clock: FrozenClock, lapi: LapiClient, router: Any
) -> None:
    act = _actuator(store, clock, lapi)
    did = _decision(store, clock)
    r = await act.apply(did)
    assert r.status is ApplyStatus.APPLIED and r.crowdsec_alert_id == "77"
    pushed = json.loads(_pushes(router)[0].request.content)
    assert pushed[0]["decisions"][0]["value"] == IP
    row = store.decisions.get(did)
    assert row is not None and row.applied_at is not None
    assert row.idempotency_key == idempotency_key(row.incident_id, "ban", IP)
    # same decision again, and a second decision for the same incident/action/ip
    assert (await act.apply(did)).status is ApplyStatus.ALREADY_APPLIED
    did2 = _decision(store, clock, incident_id=row.incident_id)
    assert (await act.apply(did2)).status is ApplyStatus.ALREADY_APPLIED
    assert len(_pushes(router)) == 1
    kinds = [e["kind"] for e in store.audit.for_incident(row.incident_id)]
    assert kinds == ["applied"]


@pytest.mark.parametrize(
    ("cfg", "kwargs", "reason"),
    [
        (Config(), {}, "not in active mode"),
        (ACTIVE, {"outcome": Outcome.APPROVAL}, "not auto"),
        (ACTIVE, {"action": Action.NOTIFY}, "does not enforce"),
        (ACTIVE, {"ip": "10.0.0.8"}, "allow-listed (rfc1918)"),
        (
            Config(mode=Mode.ACTIVE, policy=PolicyConfig(allowlist_cidrs=["203.0.113.0/24"])),
            {},
            "allow-listed (config)",
        ),
    ],
)
async def test_refusals(
    store: Store,
    clock: FrozenClock,
    lapi: LapiClient,
    router: Any,
    cfg: Config,
    kwargs: dict[str, Any],
    reason: str,
) -> None:
    act = _actuator(store, clock, lapi, cfg)
    r = await act.apply(_decision(store, clock, **kwargs))
    assert r.status is ApplyStatus.REFUSED and reason in (r.reason or "")
    assert _pushes(router) == []


async def test_rollback_by_alert_id(
    store: Store, clock: FrozenClock, lapi: LapiClient, router: Any
) -> None:
    router.get("/v1/alerts/77").mock(
        return_value=httpx.Response(200, json={"id": 77, "decisions": [{"id": 5}, {"id": 6}]})
    )
    deleted = router.delete(path__regex=r"/v1/decisions/\d+").mock(
        return_value=httpx.Response(200, json={"nbDeleted": "1"})
    )
    act = _actuator(store, clock, lapi)
    did = _decision(store, clock)
    await act.apply(did)
    rows = act.select(incident_id=store.decisions.get(did).incident_id)  # type: ignore[union-attr]
    results = await act.rollback(rows, by="user:cli:root")
    assert [r.removed for r in results] == [2]
    assert [c.request.url.path for c in deleted.calls] == ["/v1/decisions/5", "/v1/decisions/6"]
    row = store.decisions.get(did)
    assert row is not None and row.rolled_back_by == "user:cli:root"
    assert act.select(decision_id=did) == []
    # A later decision for the same incident must not silently re-ban.
    did2 = _decision(store, clock, incident_id=row.incident_id)
    assert (await act.apply(did2)).status is ApplyStatus.REFUSED


async def test_rollback_by_filter_when_alert_gone(
    store: Store, clock: FrozenClock, lapi: LapiClient, router: Any
) -> None:
    router.get("/v1/alerts/77").mock(return_value=httpx.Response(404, json={}))
    by_filter = router.delete("/v1/decisions").mock(
        return_value=httpx.Response(200, json={"nbDeleted": "1"})
    )
    act = _actuator(store, clock, lapi)
    await act.apply(_decision(store, clock))
    clock.advance(minutes=10)
    results = await act.rollback(act.select(since=timedelta(hours=1)), by="user:1")
    assert results[0].removed == 1
    params = by_filter.calls[0].request.url.params
    assert params["ip"] == IP and params["scenario"] == "nazar/ai-triage"


def test_select_needs_one_selector(store: Store, clock: FrozenClock, lapi: LapiClient) -> None:
    act = _actuator(store, clock, lapi)
    with pytest.raises(ValueError):
        act.select()
    with pytest.raises(ValueError):
        act.select(decision_id=1, incident_id="x")


async def test_reconcile_after_crash(
    store: Store, clock: FrozenClock, lapi: LapiClient, router: Any
) -> None:
    """Two decisions were keyed but never recorded as applied. One reached CrowdSec."""
    act = _actuator(store, clock, lapi)
    found = _decision(store, clock)
    missing = _decision(store, clock, ip="203.0.113.46")
    for did in (found, missing):
        row = store.decisions.get(did)
        assert row is not None
        store.decisions.set_idempotency_key(
            did, idempotency_key(row.incident_id, "ban", row.source_ip)
        )
    found_row = store.decisions.get(found)
    assert found_row is not None
    message = f"nazar {found_row.incident_id} decision {found}: ban {IP} for 4h"

    def alerts(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("ip") == IP:
            return httpx.Response(200, json=[{"id": 55, "message": message}])
        return httpx.Response(200, json=[])

    router.get("/v1/alerts").mock(side_effect=alerts)
    assert await act.reconcile() == 2
    assert store.decisions.get(found).crowdsec_alert_id == "55"  # type: ignore[union-attr]
    assert store.decisions.get(missing).crowdsec_alert_id == "77"  # type: ignore[union-attr]
    assert len(_pushes(router)) == 1


def test_cscli_argv_validated() -> None:
    req = BanRequest(IP, Action.BAN, "4h", "inc", 1)
    assert CscliDecisionBackend.add_argv(req) == [
        "cscli", "decisions", "add", "--ip", IP, "--type", "ban", "--duration", "4h",
        "--reason", "nazar/ai-triage",
    ]  # fmt: skip
    for bad in (
        BanRequest("1.2.3.4; rm -rf /", Action.BAN, "4h", "i", 1),
        BanRequest(IP, Action.NOTIFY, "4h", "i", 1),
        BanRequest(IP, Action.BAN, "4h --type x", "i", 1),
    ):
        with pytest.raises(ValueError):
            CscliDecisionBackend.add_argv(bad)
    assert CscliDecisionBackend.delete_argv(IP)[-2:] == ["--scenario", "nazar/ai-triage"]


class _FakeCscli(CscliDecisionBackend):
    def __init__(self) -> None:
        super().__init__()
        self.ran: list[list[str]] = []

    async def _run(self, argv: list[str]) -> None:
        self.ran.append(argv)


class _Failing:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    async def add(self, req: BanRequest) -> str:
        raise self.exc

    async def remove(self, crowdsec_alert_id: str, ip: str) -> int:
        return 0

    async def find(self, req: BanRequest) -> str | None:
        return None


async def test_fallback_to_cscli() -> None:
    cscli = _FakeCscli()
    backend = FallbackDecisionBackend(_Failing(LapiError("down", 500)), cscli)
    req = BanRequest(IP, Action.BAN, "4h", "inc", 1)
    assert await backend.add(req) == CSCLI_REF
    assert await backend.remove(CSCLI_REF, IP) == 1
    assert cscli.ran[0][2] == "add" and cscli.ran[1][2] == "delete"
