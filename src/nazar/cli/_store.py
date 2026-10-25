"""Opening the store for read-mostly commands, without building the whole app."""

from __future__ import annotations

from nazar.config import Config
from nazar.core.clock import SystemClock
from nazar.core.errors import NazarError
from nazar.store import Store


def open_store(cfg: Config) -> Store:
    if not cfg.store.path.exists():
        raise NazarError(f"no database at {cfg.store.path} yet: run the daemon first")
    return Store(cfg.store.path, SystemClock())
