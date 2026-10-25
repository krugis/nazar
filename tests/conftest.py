from __future__ import annotations

from pathlib import Path

import pytest

from nazar.core.clock import FrozenClock

REPO = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def store(tmp_path: Path, clock: FrozenClock):  # type: ignore[no-untyped-def]
    from nazar.store import Store

    s = Store(tmp_path / "nazar.db", clock)
    yield s
    s.close()
