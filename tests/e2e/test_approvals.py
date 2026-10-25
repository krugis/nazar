"""M3 acceptance: approvals expire safely, forged clicks are rejected, clicks are re-validated."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
import respx

from nazar.app import App, build_app
from nazar.approvals import ApprovalOutcome
from nazar.config import Config, Mode, NotifierConfig, PolicyConfig, TelegramConfig
from nazar.core.clock import FrozenClock
from nazar.daemon import Daemon
from nazar.models import ApprovalStatus
from nazar.notify import sign
from nazar.prefilter import build_allowlist
from tests.analyst.conftest import FakeBackend
from tests.conftest import FIXTURES

LAPI = "http://lapi.test"
TG = "https://api.telegram.org"
TOKEN = "123:tok"
KEY_HEX = "11" * 32
CHAT = "555"
VALID = (FIXTURES / "model_outputs" / "valid_clean.txt").read_text()


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    alerts = json.loads((FIXTURES / "lapi" / "alerts.json").read_text())
    with respx.mock(assert_all_called=False) as r:
        r.post(f"{LAPI}/v1/watchers/login").mock(
            return_value=httpx.Response(200, json={"token": "t", "expire": "2099-01-01T00:00:00Z"})
        )
        r.get(f"{LAPI}/v1/alerts").mock(return_value=httpx.Response(200, json=alerts))
        r.post(f"{LAPI}/v1/alerts").mock(return_value=httpx.Response(201, json=["900"]))
        r.post(url__regex=rf"{TG}/bot.*/sendMessage").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": {"message_id": 70}})
        )
        r.post(url__regex=rf"{TG}/bot.*/(editMessageText|answerCallbackQuery)").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": True})
        )
        yield r


@pytest.fixture
async def app(
    tmp_path: Path, clock: FrozenClock, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[App]:
    monkeypatch.setenv("NAZAR_TG_TOKEN", TOKEN)
    monkeypatch.setenv("NAZAR_HMAC_KEY", KEY_HEX)
    cfg = Config(
        mode=Mode.ACTIVE,
        notifier=NotifierConfig(telegram=TelegramConfig(enabled=True, chat_id=CHAT)),
    )
    lapi_http, tg_http = httpx.AsyncClient(base_url=LAPI), httpx.AsyncClient(base_url=TG)
    a = build_app(
        cfg,
        clock=clock,
        store_path=tmp_path / "nazar.db",
        lapi_http=lapi_http,
        telegram_http=tg_http,
        backend=FakeBackend(VALID, VALID),
        host_addresses=[],
    )
    a._clients = (lapi_http, tg_http)
    yield a
    await a.aclose()


def _pushes(router: respx.MockRouter) -> int:
    return sum(c.request.method == "POST" and c.request.url.path == "/v1/alerts"
               for c in router.calls)  # fmt: skip


def _sent_texts(router: respx.MockRouter) -> list[str]:
    return [json.loads(c.request.content)["text"] for c in router.calls
            if c.request.url.path.endswith("/sendMessage")]  # fmt: skip


async def _pending(app: App) -> str:
    """Run one cycle: without CTI, 198.51.100.7 needs approval (R8)."""
    results = {r.incident.source_ip: r for r in await Daemon(app).run_once()}
    approval_id = results["198.51.100.7"].approval_id
    assert approval_id is not None
    return approval_id


async def test_approval_message_and_approve(router: respx.MockRouter, app: App) -> None:
    approval_id = await _pending(app)
    assert any("Approval needed: ban 198.51.100.7" in t for t in _sent_texts(router))
    assert app.store.approvals.message_ref(approval_id) == f"{CHAT}:70"

    result = await app.approvals.approve(approval_id, "user:42")
    assert result.outcome is ApprovalOutcome.APPROVED
    assert result.applied is not None and result.applied.status.value == "applied"
    assert any("R10 approved by user:42" in r for r in result.reasons)
    assert _pushes(router) == 1
    # replay of the same approval does nothing
    again = await app.approvals.approve(approval_id, "user:42")
    assert again.outcome is ApprovalOutcome.NOT_PENDING and _pushes(router) == 1


async def test_expired_approval_is_safe(
    router: respx.MockRouter, app: App, clock: FrozenClock
) -> None:
    approval_id = await _pending(app)
    clock.advance(minutes=61)
    result = await app.approvals.approve(approval_id, "user:42")
    assert result.outcome is ApprovalOutcome.EXPIRED
    assert app.store.approvals.get(approval_id).status is ApprovalStatus.EXPIRED  # type: ignore[union-attr]
    assert _pushes(router) == 0
    edits = [json.loads(c.request.content)["text"] for c in router.calls
             if c.request.url.path.endswith("/editMessageText")]  # fmt: skip
    assert any("expired: no action taken" in t for t in edits)


async def test_click_is_revalidated(router: respx.MockRouter, app: App) -> None:
    approval_id = await _pending(app)
    # After the request, the operator allow-lists the range.
    app.allowlist.replace(
        build_allowlist(PolicyConfig(allowlist_cidrs=["198.51.100.0/24"]), host_addresses=[])
    )
    result = await app.approvals.approve(approval_id, "user:42")
    assert result.outcome is ApprovalOutcome.REFUSED
    assert any("R1 hard deny" in r for r in result.reasons)
    assert _pushes(router) == 0


async def test_reject(router: respx.MockRouter, app: App) -> None:
    approval_id = await _pending(app)
    assert (await app.approvals.reject(approval_id, "user:42")).outcome is ApprovalOutcome.REJECTED
    assert (await app.approvals.approve(approval_id, "user:42")).outcome is (
        ApprovalOutcome.NOT_PENDING
    )
    assert _pushes(router) == 0


def _click(router: respx.MockRouter, data: str) -> None:
    router.post(url__regex=rf"{TG}/bot.*/getUpdates").mock(
        side_effect=[
            httpx.Response(200, json={"ok": True, "result": [{"update_id": 1, "callback_query": {
                "id": "cq", "from": {"id": 42}, "data": data,
                "message": {"message_id": 70, "chat": {"id": int(CHAT)}}}}]}),
            httpx.Response(200, json={"ok": True, "result": []}),
        ]
    )  # fmt: skip


async def test_telegram_click_end_to_end(
    router: respx.MockRouter, app: App, clock: FrozenClock
) -> None:
    approval_id = await _pending(app)
    data = sign(bytes.fromhex(KEY_HEX), "a", approval_id, clock.now() + timedelta(hours=1))
    _click(router, data)
    assert app.telegram is not None
    for action in await app.telegram.poll_actions():
        await app.approvals.handle(action)
    assert _pushes(router) == 1
    assert app.store.approvals.get(approval_id).resolved_by == "user:42"  # type: ignore[union-attr]


async def test_forged_click_rejected(
    router: respx.MockRouter, app: App, clock: FrozenClock
) -> None:
    approval_id = await _pending(app)
    _click(router, sign(bytes(32), "a", approval_id, clock.now() + timedelta(hours=1)))
    assert app.telegram is not None
    assert await app.telegram.poll_actions() == []
    assert _pushes(router) == 0
    assert app.store.approvals.get(approval_id).status is ApprovalStatus.PENDING  # type: ignore[union-attr]


async def test_rollback_button(router: respx.MockRouter, app: App, clock: FrozenClock) -> None:
    router.get(f"{LAPI}/v1/alerts/900").mock(
        return_value=httpx.Response(200, json={"id": 900, "decisions": [{"id": 3}]})
    )
    router.delete(f"{LAPI}/v1/decisions/3").mock(
        return_value=httpx.Response(200, json={"nbDeleted": "1"})
    )
    approval_id = await _pending(app)
    applied = (await app.approvals.approve(approval_id, "user:42")).applied
    assert applied is not None
    data = sign(
        bytes.fromhex(KEY_HEX), "b", str(applied.decision_id), clock.now() + timedelta(hours=24)
    )
    _click(router, data)
    assert app.telegram is not None
    for action in await app.telegram.poll_actions():
        await app.approvals.handle(action)
    row = app.store.decisions.get(applied.decision_id)
    assert row is not None and row.rolled_back_by == "user:42"


async def test_daily_summary_schedule(
    router: respx.MockRouter, app: App, clock: FrozenClock
) -> None:
    daemon = Daemon(app)
    # 17:00 UTC, after 09:00: first start waits for tomorrow
    assert await daemon.daily_summary_if_due() is False
    clock.advance(hours=15)  # 08:00 next day
    assert await daemon.daily_summary_if_due() is False
    clock.advance(hours=1, minutes=1)  # 09:01
    assert await daemon.daily_summary_if_due() is True
    assert await daemon.daily_summary_if_due() is False
    assert any("Daily summary" in t for t in _sent_texts(router))
