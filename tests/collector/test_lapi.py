from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from nazar.collector import LapiClient
from nazar.core.clock import FrozenClock
from nazar.core.errors import LapiAuthError, LapiError

BASE = "http://lapi.test"


def _login(token: str = "t1", expire: str = "2026-10-25T18:00:00Z") -> httpx.Response:
    return httpx.Response(200, json={"code": 200, "expire": expire, "token": token})


@pytest.fixture
async def http() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(base_url=BASE) as client:
        yield client


@respx.mock
async def test_login_and_get_alerts(http: httpx.AsyncClient, clock: FrozenClock) -> None:
    login = respx.post(f"{BASE}/v1/watchers/login").mock(return_value=_login())
    alerts = respx.get(f"{BASE}/v1/alerts").mock(return_value=httpx.Response(200, json=[{"id": 1}]))
    lapi = LapiClient("nazar", "pw", http, clock)
    assert await lapi.get_alerts(since="1m", limit=10) == [{"id": 1}]
    assert json.loads(login.calls[0].request.content) == {
        "machine_id": "nazar",
        "password": "pw",
        "scenarios": [],
    }
    req = alerts.calls[0].request
    assert req.headers["Authorization"] == "Bearer t1"
    assert req.url.params["since"] == "1m" and req.url.params["limit"] == "10"


@respx.mock
async def test_token_refreshed_before_expiry(http: httpx.AsyncClient, clock: FrozenClock) -> None:
    login = respx.post(f"{BASE}/v1/watchers/login").mock(
        side_effect=[_login("t1", "2026-10-25T17:10:00Z"), _login("t2", "2026-10-25T18:00:00Z")]
    )
    respx.get(f"{BASE}/v1/alerts").mock(return_value=httpx.Response(200, json=[]))
    lapi = LapiClient("nazar", "pw", http, clock)
    await lapi.get_alerts(since="1m", limit=1)
    clock.advance(minutes=5)
    await lapi.get_alerts(since="1m", limit=1)
    assert login.call_count == 1
    clock.advance(minutes=4, seconds=30)  # less than 60 s left
    await lapi.get_alerts(since="1m", limit=1)
    assert login.call_count == 2


@respx.mock
async def test_401_relogin_once(http: httpx.AsyncClient, clock: FrozenClock) -> None:
    login = respx.post(f"{BASE}/v1/watchers/login").mock(return_value=_login())
    respx.get(f"{BASE}/v1/alerts").mock(
        side_effect=[httpx.Response(401), httpx.Response(200, json=[])]
    )
    lapi = LapiClient("nazar", "pw", http, clock)
    assert await lapi.get_alerts(since="1m", limit=1) == []
    assert login.call_count == 2


@respx.mock
async def test_401_twice_raises(http: httpx.AsyncClient, clock: FrozenClock) -> None:
    respx.post(f"{BASE}/v1/watchers/login").mock(return_value=_login())
    respx.get(f"{BASE}/v1/alerts").mock(return_value=httpx.Response(401))
    with pytest.raises(LapiAuthError):
        await LapiClient("nazar", "pw", http, clock).get_alerts(since="1m", limit=1)


@respx.mock
async def test_login_403(http: httpx.AsyncClient, clock: FrozenClock) -> None:
    respx.post(f"{BASE}/v1/watchers/login").mock(return_value=httpx.Response(403))
    with pytest.raises(LapiAuthError, match="not validated"):
        await LapiClient("nazar", "pw", http, clock).login()


@respx.mock
async def test_network_error_and_health(http: httpx.AsyncClient, clock: FrozenClock) -> None:
    respx.post(f"{BASE}/v1/watchers/login").mock(side_effect=httpx.ConnectError("refused"))
    lapi = LapiClient("nazar", "pw", http, clock)
    with pytest.raises(LapiError) as err:
        await lapi.login()
    assert err.value.status is None
    assert "pw" not in str(err.value)
    assert await lapi.health() is False


@respx.mock
async def test_push_get_delete(http: httpx.AsyncClient, clock: FrozenClock) -> None:
    respx.post(f"{BASE}/v1/watchers/login").mock(return_value=_login())
    respx.post(f"{BASE}/v1/alerts").mock(return_value=httpx.Response(201, json=["77"]))
    respx.get(f"{BASE}/v1/alerts/77").mock(return_value=httpx.Response(200, json={"id": 77}))
    respx.get(f"{BASE}/v1/alerts/78").mock(return_value=httpx.Response(404, json={}))
    respx.delete(f"{BASE}/v1/decisions/5").mock(
        return_value=httpx.Response(200, json={"nbDeleted": "1"})
    )
    by_filter = respx.delete(f"{BASE}/v1/decisions").mock(
        return_value=httpx.Response(200, json={"nbDeleted": "2"})
    )
    lapi = LapiClient("nazar", "pw", http, clock)
    assert await lapi.push_alerts([{"scenario": "nazar/ai-triage"}]) == ["77"]
    assert await lapi.get_alert("77") == {"id": 77}
    assert await lapi.get_alert("78") is None
    assert await lapi.delete_decision(5) == 1
    assert await lapi.delete_decisions(ip="203.0.113.45", scenario="nazar/ai-triage") == 2
    params = by_filter.calls[0].request.url.params
    assert params["ip"] == "203.0.113.45" and params["scenario"] == "nazar/ai-triage"
