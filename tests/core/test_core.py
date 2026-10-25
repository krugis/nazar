from __future__ import annotations

import io
import json
import logging
from datetime import UTC, datetime

from nazar.core import log
from nazar.core.clock import FrozenClock, from_iso, to_iso
from nazar.core.sanitize import clean, clean_line, truncate


def test_clean_strips_control_and_bidi() -> None:
    assert clean("a\x00b\x1b[31mc‮D\nE\tF") == "ab[31mcD E F"


def test_truncate() -> None:
    assert truncate("abcdef", 4) == "abc…"
    assert truncate("abc", 4) == "abc"
    assert truncate("abc", 0) == ""
    assert clean_line("x" * 500, 300).__len__() == 300


def test_iso_roundtrip_and_nanoseconds() -> None:
    value = datetime(2026, 10, 25, 17, 2, 11, tzinfo=UTC)
    assert to_iso(value) == "2026-10-25T17:02:11Z"
    assert from_iso("2026-10-25T17:02:11Z") == value
    assert from_iso("2026-10-25T17:02:11.123456789Z").microsecond == 123456
    assert from_iso("2026-10-25T20:02:11+03:00") == value


def test_frozen_clock_advance() -> None:
    clock = FrozenClock()
    start = clock.now()
    clock.advance(minutes=5)
    assert (clock.now() - start).total_seconds() == 300


def test_json_log_has_context_and_redacts() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(log.JsonFormatter())
    logger = logging.getLogger("nazar.test")
    logger.handlers[:] = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    log.redact.set(["s3cretvalue"])
    try:
        log.get_logger("nazar.test").info("lapi_login", machine="nazar", token="s3cretvalue")
    finally:
        log.redact.set([])
    record = json.loads(stream.getvalue())
    assert record["event"] == "lapi_login"
    assert record["machine"] == "nazar"
    assert record["token"] == "***"
