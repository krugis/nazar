"""SQLite connection, pragmas, migrations and transactions (LLD 03)."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from nazar.core.errors import StoreError
from nazar.store.migrations import MIGRATIONS


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def loads(value: str | None) -> Any:
    return None if value is None else json.loads(value)


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        memory = str(path) == ":memory:"
        if not memory:
            self.path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        try:
            self._conn = sqlite3.connect(
                str(path), isolation_level=None, check_same_thread=False, timeout=5.0
            )
        except sqlite3.Error as exc:
            raise StoreError(f"cannot open database {path}: {exc}") from exc
        if not memory and self.path.exists():
            os.chmod(self.path, 0o640)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._depth = 0
        for pragma in (
            "journal_mode=WAL",
            "foreign_keys=ON",
            "busy_timeout=5000",
            "synchronous=NORMAL",
        ):
            self._conn.execute(f"PRAGMA {pragma}")
        self.migrate()
        self._fix_ownership()

    def _fix_ownership(self) -> None:
        """When root opens the daemon's database (CLI), keep SQLite's side files owned by the
        database owner, or the daemon could no longer write them."""
        if str(self.path) == ":memory:" or os.geteuid() != 0 or not self.path.exists():
            return
        st = self.path.stat()
        if st.st_uid == 0:
            return
        for suffix in ("-wal", "-shm"):
            side = self.path.with_name(self.path.name + suffix)
            if side.exists():
                os.chown(side, st.st_uid, st.st_gid)

    @property
    def schema_version(self) -> int:
        return int(self._conn.execute("PRAGMA user_version").fetchone()[0])

    def migrate(self) -> None:
        with self._lock:
            current = self.schema_version
            for version, sql in MIGRATIONS:
                if version <= current:
                    continue
                try:
                    self._conn.executescript(
                        f"BEGIN IMMEDIATE;\n{sql}\nPRAGMA user_version = {version};\nCOMMIT;"
                    )
                except sqlite3.Error as exc:
                    if self._conn.in_transaction:
                        self._conn.execute("ROLLBACK")
                    raise StoreError(f"migration {version} failed: {exc}") from exc

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Re-entrant ``BEGIN IMMEDIATE`` transaction: only the outermost level commits."""
        with self._lock:
            outer = self._depth == 0
            if outer:
                self._conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield
            except BaseException:
                self._depth -= 1
                if outer:
                    self._conn.execute("ROLLBACK")
                raise
            self._depth -= 1
            if outer:
                self._conn.execute("COMMIT")

    def execute(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def one(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            row: sqlite3.Row | None = self._conn.execute(sql, params).fetchone()
            return row

    def all(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params).fetchall())

    def close(self) -> None:
        with self._lock:
            self._conn.close()
