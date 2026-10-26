from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import respx

from nazar.collector import LapiAlertSource, LapiClient, alert_to_event
from nazar.config import CollectorConfig, PrefilterConfig
from nazar.core.clock import FrozenClock
from nazar.store import Store
from tests.conftest import FIXTURES

BASE = "http://lapi.test"


def _alerts() -> list[dict[str, Any]]:
    return json.loads((FIXTURES / "lapi" / "alerts.json").read_text())


def test_normalize_ssh_alert(clock: FrozenClock) -> None:
    event = alert_to_event(_alerts()[0], now=clock.now(), max_lines=20, max_len=300)
    assert event is not None
    assert event.source_ip == "203.0.113.45"
    assert event.scenario == "crowdsecurity/ssh-bf"
    assert event.event_count == 6
    assert event.asn == "AS64500 Example Hosting" and event.country == "XX"
    assert event.crowdsec_decisions == ["ban"]
    assert event.started_at.microsecond == 123456
    # source_ip is not a sample key; control characters are stripped
    assert event.sample_lines == [
        "log_type=ssh_failed-auth service=ssh target_user=root[31m",
        "log_type=ssh_failed-auth target_user=admin",
    ]


def test_normalize_filters(clock: FrozenClock) -> None:
    results = [alert_to_event(a, now=clock.now(), max_lines=20, max_len=300) for a in _alerts()]
    kept = [e.alert_id for e in results if e is not None]
    assert kept == [101, 102]  # nazar/ alert, range scope and simulated are ignored


def test_expired_decision_not_active(clock: FrozenClock) -> None:
    alert = _alerts()[0]
    alert["decisions"][0]["until"] = "2026-10-25T16:00:00Z"  # before the frozen clock
    event = alert_to_event(alert, now=clock.now(), max_lines=20, max_len=300)
    assert event is not None and event.crowdsec_decisions == []


def test_mapped_ipv6_and_caps(clock: FrozenClock) -> None:
    alert = _alerts()[1] | {
        "source": {"scope": "ip", "value": "::ffff:198.51.100.7"},
        "events": [{"meta": [{"key": "http_path", "value": "/" + "a" * 500}]}] * 5,
    }
    event = alert_to_event(alert, now=clock.now(), max_lines=3, max_len=50)
    assert event is not None
    assert event.source_ip == "198.51.100.7"
    assert len(event.sample_lines) == 3 and all(len(x) <= 50 for x in event.sample_lines)


@pytest.mark.parametrize(
    "alert",
    [
        {"scenario": "x", "source": {"scope": "Ip", "value": "1.2.3.4"}},
        {"id": 1, "scenario": "x", "source": {"scope": "Ip", "value": "not-an-ip"}},
        {"id": 1, "source": {"scope": "Ip", "value": "1.2.3.4"}},
    ],
)
def test_malformed_ignored(alert: dict[str, Any], clock: FrozenClock) -> None:
    assert alert_to_event(alert, now=clock.now(), max_lines=1, max_len=100) is None


@pytest.fixture
async def http() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(base_url=BASE) as client:
        yield client


@respx.mock
async def test_poll_cursor_and_seen(
    http: httpx.AsyncClient, store: Store, clock: FrozenClock
) -> None:
    respx.post(f"{BASE}/v1/watchers/login").mock(
        return_value=httpx.Response(200, json={"token": "t", "expire": "2026-10-26T00:00:00Z"})
    )
    route = respx.get(f"{BASE}/v1/alerts").mock(return_value=httpx.Response(200, json=_alerts()))
    source = LapiAlertSource(
        LapiClient("nazar", "pw", http, clock), store, clock, CollectorConfig(), PrefilterConfig()
    )
    first = await source.poll()
    assert [e.alert_id for e in first.events] == [101, 102]
    assert first.cursor == 105 and first.ignored == 3
    assert route.calls[0].request.url.params["since"] == "61m"  # lookback + 2 x interval
    source.commit(first)

    clock.advance(seconds=30)
    second = await source.poll()
    assert second.events == [] and second.cursor == 105
    assert route.calls[1].request.url.params["since"] == "90s"


@respx.mock
async def test_poll_truncated(http: httpx.AsyncClient, store: Store, clock: FrozenClock) -> None:
    respx.post(f"{BASE}/v1/watchers/login").mock(
        return_value=httpx.Response(200, json={"token": "t", "expire": "2026-10-26T00:00:00Z"})
    )
    respx.get(f"{BASE}/v1/alerts").mock(return_value=httpx.Response(200, json=_alerts()[:2]))
    source = LapiAlertSource(
        LapiClient("nazar", "pw", http, clock),
        store,
        clock,
        CollectorConfig(batch_limit=2),
        PrefilterConfig(),
    )
    assert (await source.poll()).truncated


@pytest.mark.parametrize(
    ("decision", "active"),
    [
        # CrowdSec 1.8.1 as seen live: no "until", duration = remaining time
        ({"type": "ban", "duration": "3h59m59s"}, True),
        ({"type": "ban", "duration": "-24s"}, False),  # deleted or expired
        ({"type": "ban", "duration": "-1h2m3.5s"}, False),
        ({"type": "ban", "until": "2099-01-01T00:00:00Z", "duration": "-1s"}, True),  # until wins
        ({"type": "ban", "until": "2020-01-01T00:00:00Z"}, False),
        ({"type": "ban"}, True),  # nothing known: assume active (conservative for R5)
        ({"type": "ban", "duration": "4h", "simulated": True}, False),
    ],
)
def test_decision_activity(clock: FrozenClock, decision: dict[str, Any], active: bool) -> None:
    alert = _alerts()[0] | {"decisions": [decision]}
    event = alert_to_event(alert, now=clock.now(), max_lines=20, max_len=300)
    assert event is not None
    assert (event.crowdsec_decisions == ["ban"]) is active
