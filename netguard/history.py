"""Event log + per-day traffic totals in SQLite."""
from __future__ import annotations

import datetime as dt
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)

EVENT_KINDS = (
    "block", "unblock", "expire", "rule_on", "rule_off", "killswitch_on", "killswitch_off",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    exe TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS usage (
    day TEXT NOT NULL,
    key TEXT NOT NULL,
    name TEXT NOT NULL,
    exe TEXT NOT NULL DEFAULT '',
    bytes_in INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, key)
);
"""


@dataclass(frozen=True)
class Event:
    ts: float
    kind: str
    name: str
    exe: str
    detail: str


@dataclass(frozen=True)
class UsageRow:
    name: str
    exe: str
    bytes_in: int
    bytes_out: int

    @property
    def total(self) -> int:
        return self.bytes_in + self.bytes_out


class HistoryStore:
    def __init__(self, path: Path | str = ":memory:", clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _day(self, ts: float | None = None) -> str:
        return dt.date.fromtimestamp(self._clock() if ts is None else ts).isoformat()

    def log_event(self, kind: str, name: str = "", exe: str = "", detail: str = "") -> None:
        if kind not in EVENT_KINDS:
            raise ValueError(kind)
        try:
            with self._lock:
                self._db.execute(
                    "INSERT INTO events(ts, kind, name, exe, detail) VALUES (?, ?, ?, ?, ?)",
                    (self._clock(), kind, name, exe, detail),
                )
                self._db.commit()
        except sqlite3.Error as exc:
            log.error("history write failed: %s", exc)

    def add_usage(self, items: list[tuple[str, str, str, int, int]]) -> None:
        """items: (key, name, exe, bytes_in, bytes_out) deltas."""
        rows = [(self._day(), k, n, e, int(i), int(o)) for k, n, e, i, o in items if i > 0 or o > 0]
        if not rows:
            return
        try:
            with self._lock:
                self._db.executemany(
                    "INSERT INTO usage(day, key, name, exe, bytes_in, bytes_out) VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(day, key) DO UPDATE SET bytes_in = bytes_in + excluded.bytes_in, "
                    "bytes_out = bytes_out + excluded.bytes_out, name = excluded.name",
                    rows,
                )
                self._db.commit()
        except sqlite3.Error as exc:
            log.error("usage write failed: %s", exc)

    def recent_events(self, limit: int = 500, kind: str | None = None) -> list[Event]:
        sql = "SELECT ts, kind, name, exe, detail FROM events"
        args: tuple = ()
        if kind:
            sql += " WHERE kind = ?"
            args = (kind,)
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        with self._lock:
            return [Event(*row) for row in self._db.execute(sql, (*args, limit))]

    def top_usage(self, days: int = 1, limit: int = 100) -> list[UsageRow]:
        first_day = self._day(self._clock() - (days - 1) * 86400)
        with self._lock:
            rows = self._db.execute(
                "SELECT MAX(name), MAX(exe), SUM(bytes_in), SUM(bytes_out) FROM usage "
                "WHERE day >= ? GROUP BY key ORDER BY SUM(bytes_in) + SUM(bytes_out) DESC LIMIT ?",
                (first_day, limit),
            ).fetchall()
        return [UsageRow(*row) for row in rows]

    def prune(self, keep_days: int) -> None:
        cutoff = self._clock() - keep_days * 86400
        try:
            with self._lock:
                self._db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
                self._db.execute("DELETE FROM usage WHERE day < ?", (self._day(cutoff),))
                self._db.commit()
        except sqlite3.Error as exc:
            log.error("history prune failed: %s", exc)
