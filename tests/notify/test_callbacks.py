from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from nazar.notify import CallbackError, load_key, sign, verify

KEY = bytes(range(32))
NOW = datetime(2026, 10, 25, 17, 0, tzinfo=UTC)
LATER = NOW + timedelta(hours=1)


def test_round_trip_and_size() -> None:
    data = sign(KEY, "a", "abcDEF12345", LATER)
    assert len(data.encode()) <= 64
    cb = verify(KEY, data, NOW)
    assert (cb.op, cb.ref) == ("a", "abcDEF12345")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.replace("|a|", "|b|"),  # change op
        lambda d: d.replace("abcDEF12345", "abcDEF12346"),  # change ref
        lambda d: d[:-1] + ("A" if d[-1] != "A" else "B"),  # change signature
        lambda d: d.replace("n1|", "n2|"),  # version
        lambda d: (
            d.rsplit("|", 2)[0]
            + f"|{int((LATER + timedelta(days=9)).timestamp())}|"
            + d.rsplit("|", 1)[1]
        ),  # extend expiry
        lambda d: d + "|extra",
        lambda d: "",
    ],
)
def test_tampering_rejected(mutate) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(CallbackError):
        verify(KEY, mutate(sign(KEY, "a", "abcDEF12345", LATER)), NOW)


def test_other_key_and_expiry() -> None:
    data = sign(KEY, "r", "abcDEF12345", LATER)
    with pytest.raises(CallbackError, match="signature"):
        verify(bytes(32), data, NOW)
    with pytest.raises(CallbackError, match="expired"):
        verify(KEY, data, LATER)


def test_sign_validates_input() -> None:
    with pytest.raises(ValueError):
        sign(KEY, "a", "has|pipe", LATER)
    with pytest.raises(ValueError):
        sign(KEY, "x", "ref", LATER)  # type: ignore[arg-type]


def test_load_key() -> None:
    assert load_key("00" * 32) == bytes(32)
    assert load_key("abcd") is None  # too short
    assert load_key("zz" * 32) is None
    assert load_key(None) is None
