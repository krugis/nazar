"""Telegram Bot API notifier with signed approval buttons (LLD 10).

Long polling (``getUpdates``) only, so no inbound port is needed. The bot token is part of
every URL, so errors never include URLs.
"""

from __future__ import annotations

from typing import Any

import httpx

from nazar.config import TelegramConfig
from nazar.core.clock import Clock
from nazar.core.errors import NotifierError
from nazar.core.log import get_logger
from nazar.core.sanitize import clean_line
from nazar.models import Actor, user_actor
from nazar.notify.base import UserAction
from nazar.notify.callbacks import CallbackError, sign, verify
from nazar.notify.messages import Note, buttons, render
from nazar.store import Store

log = get_logger(__name__)

API_URL = "https://api.telegram.org"
OFFSET_KEY = "tg.offset"
POLL_TIMEOUT_S = 30
MAX_TEXT = 4000  # Telegram's limit is 4096 characters


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class TelegramNotifier:
    name = "telegram"

    def __init__(
        self,
        cfg: TelegramConfig,
        http: httpx.AsyncClient,
        token: str,
        hmac_key: bytes,
        store: Store,
        clock: Clock,
    ) -> None:
        self._cfg = cfg
        self._http = http
        self._token = token
        self._key = hmac_key
        self._store = store
        self._clock = clock

    async def _call(self, method: str, payload: dict[str, Any], timeout: float = 15) -> Any:
        try:
            resp = await self._http.post(
                f"/bot{self._token}/{method}", json=payload, timeout=timeout
            )
        except httpx.HTTPError as exc:
            raise NotifierError(f"telegram {method}: {type(exc).__name__}") from None
        try:
            data = resp.json()
        except ValueError:
            raise NotifierError(f"telegram {method}: HTTP {resp.status_code}") from None
        if not isinstance(data, dict) or not data.get("ok"):
            desc = clean_line(
                str(data.get("description", "")) if isinstance(data, dict) else "", 200
            )
            raise NotifierError(f"telegram {method} failed: {desc or resp.status_code}")
        return data.get("result")

    # ------------------------------------------------------------------ outgoing

    def _keyboard(self, note: Note) -> dict[str, Any] | None:
        row = [
            {"text": b.label, "callback_data": sign(self._key, b.op, b.ref, b.expires)}
            for b in buttons(note)
        ]
        return {"inline_keyboard": [row]} if row else None

    async def send(self, note: Note) -> str | None:
        payload: dict[str, Any] = {
            "chat_id": self._cfg.chat_id,
            "text": render(note)[:MAX_TEXT],
            "disable_web_page_preview": True,
        }
        keyboard = self._keyboard(note)
        if keyboard:
            payload["reply_markup"] = keyboard
        result = await self._call("sendMessage", payload)
        message_id = result.get("message_id") if isinstance(result, dict) else None
        return f"{self._cfg.chat_id}:{message_id}" if message_id is not None else None

    async def mark_resolved(self, message_ref: str, text: str) -> None:
        chat_id, _, message_id = message_ref.rpartition(":")
        if not chat_id or not message_id.isdigit():
            return
        # Editing the text without reply_markup also removes the buttons.
        await self._call(
            "editMessageText",
            {"chat_id": chat_id, "message_id": int(message_id), "text": text[:MAX_TEXT]},
        )

    # ------------------------------------------------------------------ incoming

    def _check(self, cq: dict[str, Any]) -> tuple[UserAction | None, str]:
        message = _dict(cq.get("message"))
        chat = _dict(message.get("chat"))
        sender = _dict(cq.get("from"))
        chat_id, user_id = str(chat.get("id", "")), sender.get("id")
        if chat_id != str(self._cfg.chat_id):
            return None, "wrong_chat"
        if self._cfg.allowed_user_ids and user_id not in self._cfg.allowed_user_ids:
            return None, "user_not_allowed"
        try:
            data = verify(self._key, str(cq.get("data", "")), self._clock.now())
        except CallbackError as exc:
            return None, str(exc)
        ref = f"{chat_id}:{message.get('message_id')}" if message.get("message_id") else None
        return UserAction(data.op, data.ref, user_actor(str(user_id)), ref), "ok"

    async def poll_actions(self) -> list[UserAction]:
        offset = int(self._store.kv.get(OFFSET_KEY, 0))
        updates = await self._call(
            "getUpdates",
            {"offset": offset, "timeout": POLL_TIMEOUT_S, "allowed_updates": ["callback_query"]},
            timeout=POLL_TIMEOUT_S + 10,
        )
        actions: list[UserAction] = []
        for update in updates if isinstance(updates, list) else []:
            if not isinstance(update, dict):
                continue
            offset = max(offset, int(update.get("update_id", 0)) + 1)
            cq = update.get("callback_query")
            if not isinstance(cq, dict):
                continue
            action, reason = self._check(cq)
            if action is None:
                sender = _dict(cq.get("from"))
                self._store.audit.append(
                    Actor.SYSTEM, "callback_rejected",
                    {"reason": reason, "user": sender.get("id")},
                )  # fmt: skip
                log.warning("callback_rejected", reason=reason)
            else:
                actions.append(action)
            try:
                await self._call(
                    "answerCallbackQuery",
                    {"callback_query_id": cq.get("id"),
                     "text": "Received" if action else "Not allowed"},
                )  # fmt: skip
            except NotifierError as exc:
                log.debug("callback_answer_failed", error=str(exc))
        self._store.kv.set(OFFSET_KEY, offset)
        return actions
