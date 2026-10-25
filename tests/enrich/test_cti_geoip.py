from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import respx

from nazar.core.clock import FrozenClock
from nazar.core.errors import CtiError
from nazar.enrich import CtiProvider, GeoIpProvider
from nazar.models import Incident
from nazar.store import Store
from tests.conftest import FIXTURES

CTI = "http://cti.test/v2"
IP = "198.51.100.7"
SMOKE = json.loads((FIXTURES / "cti" / "smoke_malicious.json").read_text())


def _incident(ip: str = IP) -> Incident:
    ts = datetime(2026, 10, 25, tzinfo=UTC)
    return Incident(
        incident_id="inc", source_ip=ip, first_seen=ts, last_seen=ts, scenarios=["s"], event_count=1
    )


@pytest.fixture
async def http() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(base_url=CTI) as client:
        yield client


@respx.mock
async def test_cti_malicious_cached(
    http: httpx.AsyncClient, store: Store, clock: FrozenClock
) -> None:
    route = respx.get(f"{CTI}/smoke/{IP}").mock(return_value=httpx.Response(200, json=SMOKE))
    cti = CtiProvider(store, http, clock, "key")
    result = await cti.enrich(_incident(), [])
    assert result == {
        "cti_reputation": "malicious",
        "cti_behaviors": ["http:scan", "http:exploit"],  # bidi override stripped
        "cti_classifications": ["scanner:alphastrike", "fp:seo:crawler"],
        "country": "YY",
        "asn": "AS64501 Example Transit",
    }
    assert route.calls[0].request.headers["X-Api-Key"] == "key"
    await cti.enrich(_incident(), [])
    assert route.call_count == 1  # cache hit
    clock.advance(hours=25)
    await cti.enrich(_incident(), [])
    assert route.call_count == 2


@respx.mock
async def test_cti_404_cached_as_unknown(
    http: httpx.AsyncClient, store: Store, clock: FrozenClock
) -> None:
    respx.get(f"{CTI}/smoke/{IP}").mock(return_value=httpx.Response(404, json={}))
    result = await CtiProvider(store, http, clock, "key").enrich(_incident(), [])
    assert result["cti_reputation"] == "unknown"
    assert store.cti_cache.get(IP, max_age=timedelta(hours=1))


@respx.mock
async def test_cti_429_pauses(http: httpx.AsyncClient, store: Store, clock: FrozenClock) -> None:
    route = respx.get(f"{CTI}/smoke/{IP}").mock(return_value=httpx.Response(429))
    cti = CtiProvider(store, http, clock, "key")
    assert await cti.enrich(_incident(), []) == {}
    await cti.enrich(_incident(), [])
    assert route.call_count == 1
    clock.advance(minutes=6)
    await cti.enrich(_incident(), [])
    assert route.call_count == 2


@respx.mock
async def test_cti_key_rejected(http: httpx.AsyncClient, store: Store, clock: FrozenClock) -> None:
    route = respx.get(f"{CTI}/smoke/{IP}").mock(return_value=httpx.Response(403))
    cti = CtiProvider(store, http, clock, "bad")
    assert await cti.enrich(_incident(), []) == {}
    assert cti.key_rejected
    await cti.enrich(_incident(), [])
    assert route.call_count == 1


@respx.mock
@pytest.mark.parametrize("resp", [httpx.Response(500), httpx.Response(200, text="nope")])
async def test_cti_errors(
    http: httpx.AsyncClient, store: Store, clock: FrozenClock, resp: httpx.Response
) -> None:
    respx.get(f"{CTI}/smoke/{IP}").mock(return_value=resp)
    with pytest.raises(CtiError):
        await CtiProvider(store, http, clock, "key").enrich(_incident(), [])


async def test_geoip_lookups() -> None:
    def country(ip: str) -> dict[str, Any]:
        return {"country": "TR"}

    def asn(ip: str) -> dict[str, Any]:
        raise ValueError("not found")

    provider = GeoIpProvider(country, asn)
    assert await provider.enrich(_incident(), []) == {"country": "TR"}


def test_geoip_disabled_without_paths_or_package(tmp_path: Any) -> None:
    assert GeoIpProvider.from_paths(None, None) is None
    # geoip2 is an optional extra and is not installed in the test environment
    assert GeoIpProvider.from_paths(tmp_path / "GeoLite2-Country.mmdb", None) is None
