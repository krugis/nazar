from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import httpx
import pytest
import respx

from nazar.config import TelegramConfig
from nazar.core.clock import FrozenClock
from nazar.core.errors import NotifierError
from nazar.notify import ApprovalNote, HealthNote, TelegramNotifier, sign, verify
from nazar.store import Store

TG = "https://api.telegram.org"
TOKEN = "123:secret-token"
KEY = bytes(range(32))
CHAT = "-1001234"


@pytest.fixture
async def http() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(base_url=TG) as client:
        yield client


def _tg(http: httpx.AsyncClient, store: Store, clock: FrozenClock, **cfg: Any) -> TelegramNotifier:
    return TelegramNotifier(TelegramConfig(enabled=True, chat_id=CHAT, **cfg), http, TOKEN, KEY,
                            store, clock)  # fmt: skip


def _note(clock: FrozenClock) -> ApprovalNote:
    return ApprovalNote(incident_id="inc_1", ip="198.51.100.7", scenarios=["s"], action="ban",
                        duration="4h", verdict="malicious", severity="high", confidence=0.9,
                        summary="x", approval_id="abcDEF12345",
                        expires_at=clock.now() + timedelta(hours=1))  # fmt: skip


@respx.mock
async def test_send_with_signed_buttons(
    http: httpx.AsyncClient, store: Store, clock: FrozenClock
) -> None:
    route = respx.post(f"{TG}/bot{TOKEN}/sendMessage").mock(
        return_value=httpx.Response(200, json={"ok": True, "result": {"message_id": 7}})
    )
    ref = await _tg(http, store, clock).send(_note(clock))
    assert ref == f"{CHAT}:7"
    body = json.loads(route.calls[0].request.content)
    assert body["chat_id"] == CHAT and "parse_mode" not in body
    keys = body["reply_markup"]["inline_keyboard"][0]
    assert [k["text"] for k in keys] == ["Approve", "Reject"]
    assert verify(KEY, keys[0]["callback_data"], clock.now()).op == "a"


@respx.mock
async def test_errors_never_leak_token(
    http: httpx.AsyncClient, store: Store, clock: FrozenClock
) -> None:
    respx.post(f"{TG}/bot{TOKEN}/sendMessage").mock(
        side_effect=httpx.ConnectError(f"{TG}/bot{TOKEN}")
    )
    with pytest.raises(NotifierError) as err:
        await _tg(http, store, clock).send(HealthNote(component="x", state="down"))
    assert TOKEN not in str(err.value)
    respx.post(f"{TG}/bot{TOKEN}/sendMessage").mock(
        return_value=httpx.Response(401, json={"ok": False, "description": "Unauthorized"})
    )
    with pytest.raises(NotifierError, match="Unauthorized"):
        await _tg(http, store, clock).send(HealthNote(component="x", state="down"))


def _update(uid: int, data: str, chat: str = CHAT, user: int = 42) -> dict[str, Any]:
    return {"update_id": uid, "callback_query": {
        "id": f"cq{uid}", "from": {"id": user}, "data": data,
        "message": {"message_id": 7, "chat": {"id": int(chat)}}}}  # fmt: skip


@respx.mock
async def test_poll_verifies_every_click(
    http: httpx.AsyncClient, store: Store, clock: FrozenClock
) -> None:
    good = sign(KEY, "a", "abcDEF12345", clock.now() + timedelta(hours=1))
    expired = sign(KEY, "a", "abcDEF12345", clock.now() - timedelta(seconds=1))
    forged = sign(bytes(32), "a", "abcDEF12345", clock.now() + timedelta(hours=1))
    updates = [
        _update(10, good),
        _update(11, good, chat="-999"),
        _update(12, forged),
        _update(13, expired),
        _update(14, good, user=666),
        {"update_id": 15, "message": {"text": "hi"}},
    ]
    poll = respx.post(f"{TG}/bot{TOKEN}/getUpdates").mock(
        return_value=httpx.Response(200, json={"ok": True, "result": updates})
    )
    answers = respx.post(f"{TG}/bot{TOKEN}/answerCallbackQuery").mock(
        return_value=httpx.Response(200, json={"ok": True, "result": True})
    )
    tg = _tg(http, store, clock, allowed_user_ids=[42])
    actions = await tg.poll_actions()
    assert [(a.op, a.ref, a.user, a.message_ref) for a in actions] == [
        ("a", "abcDEF12345", "user:42", f"{CHAT}:7")
    ]
    texts = [json.loads(c.request.content)["text"] for c in answers.calls]
    assert texts == ["Received"] + ["Not allowed"] * 4
    rejected = store.db.all("SELECT detail FROM audit_log WHERE kind = 'callback_rejected'")
    reasons = [json.loads(r["detail"])["reason"] for r in rejected]
    assert reasons == ["wrong_chat", "bad signature", "expired", "user_not_allowed"]
    assert store.kv.get("tg.offset") == 16
    await tg.poll_actions()
    assert json.loads(poll.calls[1].request.content)["offset"] == 16


@respx.mock
async def test_mark_resolved_edits_text(
    http: httpx.AsyncClient, store: Store, clock: FrozenClock
) -> None:
    route = respx.post(f"{TG}/bot{TOKEN}/editMessageText").mock(
        return_value=httpx.Response(200, json={"ok": True, "result": {}})
    )
    await _tg(http, store, clock).mark_resolved(f"{CHAT}:7", "done")
    assert json.loads(route.calls[0].request.content) == {
        "chat_id": CHAT,
        "message_id": 7,
        "text": "done",
    }
