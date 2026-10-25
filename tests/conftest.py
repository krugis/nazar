from __future__ import annotations

from pathlib import Path

import pytest

from nazar.core.clock import FrozenClock

REPO = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()
