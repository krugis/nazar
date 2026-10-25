"""Notifier interfaces and fan-out (LLD 10)."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from nazar.core.errors import NotifierError
from nazar.core.log import get_logger
from nazar.notify.messages import Note

log = get_logger(__name__)

SEND_ATTEMPTS = 3


@dataclass(frozen=True)
class UserAction:
    """A verified button click."""

    op: Literal["a", "r", "b"]
    ref: str
    user: str
    """Audit actor, e.g. ``user:123456``."""
    message_ref: str | None = None


@runtime_checkable
class Notifier(Protocol):
    name: str

    async def send(self, note: Note) -> str | None:
        """Deliver a notification. Returns a message reference if it can be edited later."""
        ...


@runtime_checkable
class InteractiveNotifier(Notifier, Protocol):
    async def poll_actions(self) -> list[UserAction]:
        """Verified clicks since the last poll. Rejected clicks are handled internally."""
        ...

    async def mark_resolved(self, message_ref: str, text: str) -> None: ...


class FanoutNotifier:
    """Sends to every notifier. A failing notifier never affects the others."""

    name = "fanout"

    def __init__(self, notifiers: Sequence[Notifier], retry_delay_s: float = 2.0) -> None:
        self.notifiers = list(notifiers)
        self._delay = retry_delay_s

    async def _send_one(self, notifier: Notifier, note: Note) -> str | None:
        for attempt in range(1, SEND_ATTEMPTS + 1):
            try:
                return await notifier.send(note)
            except NotifierError as exc:
                if attempt == SEND_ATTEMPTS:
                    log.error("notify_failed", notifier=notifier.name, kind=note.kind,
                              error=str(exc))  # fmt: skip
                    return None
                await asyncio.sleep(self._delay * attempt)
        return None

    async def send(self, note: Note) -> str | None:
        refs = await asyncio.gather(*(self._send_one(n, note) for n in self.notifiers))
        return next((r for r in refs if r), None)

    @property
    def interactive(self) -> list[InteractiveNotifier]:
        return [n for n in self.notifiers if isinstance(n, InteractiveNotifier)]

    async def mark_resolved(self, message_ref: str, text: str) -> None:
        for notifier in self.interactive:
            try:
                await notifier.mark_resolved(message_ref, text)
            except NotifierError as exc:
                log.warning("notify_edit_failed", notifier=notifier.name, error=str(exc))
