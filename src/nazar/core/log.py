"""JSON logging on top of stdlib ``logging`` with secret redaction (LLD 00, decision D1)."""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Iterable, MutableMapping
from datetime import UTC, datetime
from typing import Any

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


class _Redactor:
    def __init__(self) -> None:
        self._secrets: list[str] = []

    def set(self, secrets: Iterable[str | None]) -> None:
        # Longest first so a secret containing another is fully replaced.
        self._secrets = sorted({s for s in secrets if s and len(s) >= 4}, key=len, reverse=True)

    def __call__(self, text: str) -> str:
        for value in self._secrets:
            text = text.replace(value, "***")
        return text


redact = _Redactor()


def _context(record: logging.LogRecord) -> dict[str, Any]:
    return {k: v for k, v in record.__dict__.items() if k not in _RESERVED}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        payload.update(_context(record))
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return redact(json.dumps(payload, default=str, ensure_ascii=False))


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ctx = " ".join(f"{k}={v}" for k, v in _context(record).items())
        line = f"{record.levelname.lower():7} {record.getMessage()}" + (f"  {ctx}" if ctx else "")
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return redact(line)


class KwLogger(logging.LoggerAdapter[logging.Logger]):
    """``log.info("event_name", key=value)`` puts keyword arguments into the log record."""

    def process(
        self, msg: Any, kwargs: MutableMapping[str, Any]
    ) -> tuple[Any, MutableMapping[str, Any]]:
        std = {k: kwargs.pop(k) for k in ("exc_info", "stack_info", "stacklevel") if k in kwargs}
        extra = dict(kwargs)
        kwargs.clear()
        kwargs.update(std)
        kwargs["extra"] = extra
        return msg, kwargs


def get_logger(name: str) -> KwLogger:
    return KwLogger(logging.getLogger(name), {})


def setup_logging(level: str = "info", fmt: str = "json") -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # httpx logs full request URLs at INFO, and Telegram URLs contain the bot token.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
