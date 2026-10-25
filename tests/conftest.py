from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from nazar.core.clock import FrozenClock

REPO = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(autouse=True)
def _isolate_environ() -> Iterator[None]:
    """``load_secrets`` writes into os.environ; never let that leak between tests."""
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def store(tmp_path: Path, clock: FrozenClock):  # type: ignore[no-untyped-def]
    from nazar.store import Store

    s = Store(tmp_path / "nazar.db", clock)
    yield s
    s.close()
