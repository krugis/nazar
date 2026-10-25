"""Writes every notification to the log. Always enabled."""

from __future__ import annotations

from nazar.core.log import get_logger
from nazar.notify.messages import Note, render

log = get_logger("nazar.notify")


class LogNotifier:
    name = "log"

    async def send(self, note: Note) -> str | None:
        log.info("notification", kind=note.kind, text=render(note))
        return None
