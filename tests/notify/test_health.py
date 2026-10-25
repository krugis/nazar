from __future__ import annotations

from nazar.core.clock import FrozenClock
from nazar.notify import HealthMonitor, HealthNote, Note


class _Collect:
    name = "collect"

    def __init__(self) -> None:
        self.sent: list[HealthNote] = []

    async def send(self, note: Note) -> str | None:
        assert isinstance(note, HealthNote)
        self.sent.append(note)
        return None


async def test_changes_and_repeats(clock: FrozenClock) -> None:
    out = _Collect()
    mon = HealthMonitor(clock, out)
    await mon.update("lapi", "up")  # healthy first observation: silent
    await mon.update("lapi", "up")
    assert out.sent == []
    await mon.update("lapi", "down", "refused")
    await mon.update("lapi", "down", "refused")  # no repeat within 15 min
    clock.advance(minutes=16)
    await mon.update("lapi", "down", "refused")  # repeat while down
    await mon.update("lapi", "up")  # recovery is reported
    assert [n.state for n in out.sent] == ["down", "down", "up"]
    await mon.update("ollama", "down")  # unhealthy first observation is reported
    assert out.sent[-1].component == "ollama"
    assert mon.snapshot() == {"lapi": "up", "ollama": "down"}
