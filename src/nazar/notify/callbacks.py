"""Signed button data for interactive notifiers (LLD 10).

Format (at most 64 bytes, Telegram's ``callback_data`` limit)::

    n1|<op>|<ref>|<exp>|<sig>      sig = base64url(HMAC-SHA256(key, "n1|op|ref|exp"))[:16]
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast

VERSION = "n1"
MAX_BYTES = 64
_REF = re.compile(r"^[A-Za-z0-9_-]{1,24}$")
Op = Literal["a", "r", "b"]


class CallbackError(ValueError):
    """Rejected button data; the message is safe to log."""


@dataclass(frozen=True)
class CallbackData:
    op: Op
    ref: str
    expires: datetime


def _sig(key: bytes, payload: str) -> str:
    digest = hmac.new(key, payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")[:16]


def sign(key: bytes, op: Op, ref: str, expires: datetime) -> str:
    if op not in ("a", "r", "b") or not _REF.match(ref):
        raise ValueError("invalid callback op or ref")
    payload = f"{VERSION}|{op}|{ref}|{int(expires.timestamp())}"
    data = f"{payload}|{_sig(key, payload)}"
    if len(data.encode()) > MAX_BYTES:
        raise ValueError("callback data too long")
    return data


def verify(key: bytes, data: str, now: datetime) -> CallbackData:
    if len(data.encode()) > MAX_BYTES:
        raise CallbackError("too long")
    parts = data.split("|")
    if len(parts) != 5 or parts[0] != VERSION:
        raise CallbackError("malformed")
    _, op, ref, exp, sig = parts
    if op not in ("a", "r", "b") or not _REF.match(ref) or not exp.isdigit():
        raise CallbackError("malformed")
    if not hmac.compare_digest(sig, _sig(key, f"{VERSION}|{op}|{ref}|{exp}")):
        raise CallbackError("bad signature")
    expires = datetime.fromtimestamp(int(exp), UTC)
    if now >= expires:
        raise CallbackError("expired")
    return CallbackData(cast(Op, op), ref, expires)


def load_key(hex_key: str | None) -> bytes | None:
    """The HMAC key from ``NAZAR_HMAC_KEY`` (hex). Short or invalid keys are refused."""
    if not hex_key:
        return None
    try:
        key = bytes.fromhex(hex_key.strip())
    except ValueError:
        return None
    return key if len(key) >= 16 else None
