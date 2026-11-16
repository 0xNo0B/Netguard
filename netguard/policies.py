"""Permanent and scheduled block rules."""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path

from .blocker import DesiredBlock
from .firewall import make_rule_id

log = logging.getLogger(__name__)

ALL_DAYS = (0, 1, 2, 3, 4, 5, 6)  # Python weekday(): Monday=0 ... Sunday=6
KINDS = ("always", "schedule")


def parse_hhmm(text: str) -> int:
    hours, _, minutes = text.partition(":")
    value = int(hours) * 60 + int(minutes)
    if not 0 <= value < 24 * 60:
        raise ValueError(text)
    return value


def format_hhmm(minutes: int) -> str:
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


@dataclass
class Policy:
    exe: str
    name: str
    kind: str = "always"
    days: list[int] = field(default_factory=lambda: list(ALL_DAYS))
    start: int = 0  # minutes after midnight
    end: int = 0  # start == end -> the whole day
    enabled: bool = True
    package_sid: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown kind {self.kind}")
        self.days = sorted({int(d) for d in self.days if 0 <= int(d) <= 6})
        self.start = int(self.start) % 1440
        self.end = int(self.end) % 1440

    @property
    def rule_id(self) -> str:
        return make_rule_id(self.exe)

    def is_active(self, now: dt.datetime) -> bool:
        if not self.enabled:
            return False
        if self.kind == "always":
            return True
        minute = now.hour * 60 + now.minute
        today = now.weekday()
        yesterday = (today - 1) % 7
        if self.start == self.end:  # whole selected days
            return today in self.days
        if self.start < self.end:
            return today in self.days and self.start <= minute < self.end
        # window crosses midnight, e.g. 23:00 -> 06:00; it "belongs" to the start day
        return (today in self.days and minute >= self.start) or (yesterday in self.days and minute < self.end)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


def desired_blocks(policies: list[Policy], now: dt.datetime) -> dict[str, DesiredBlock]:
    grouped: dict[str, list[Policy]] = {}
    for policy in policies:
        if policy.exe and policy.is_active(now):
            grouped.setdefault(policy.rule_id, []).append(policy)
    return {
        rule_id: DesiredBlock(items[0].exe, items[0].name, items[0].package_sid, tuple(p.id for p in items))
        for rule_id, items in grouped.items()
    }


class PolicyStore:
    def __init__(self, path: Path | None) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._items: list[Policy] = self._load()

    def all(self) -> list[Policy]:
        with self._lock:
            return [replace(p, days=list(p.days)) for p in self._items]

    def get(self, policy_id: str) -> Policy | None:
        with self._lock:
            return next((replace(p) for p in self._items if p.id == policy_id), None)

    def upsert(self, policy: Policy) -> None:
        with self._lock:
            for i, existing in enumerate(self._items):
                if existing.id == policy.id:
                    self._items[i] = policy
                    break
            else:
                self._items.append(policy)
            self._save_locked()

    def delete(self, policy_id: str) -> None:
        with self._lock:
            self._items = [p for p in self._items if p.id != policy_id]
            self._save_locked()

    def set_enabled(self, policy_id: str, enabled: bool) -> None:
        with self._lock:
            for p in self._items:
                if p.id == policy_id:
                    p.enabled = enabled
            self._save_locked()

    def _load(self) -> list[Policy]:
        if self._path is None or not self._path.exists():
            return []
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return [Policy.from_dict(item) for item in data.get("policies", [])]
        except (OSError, ValueError, TypeError, KeyError) as exc:
            log.error("Corrupt policies file %s: %s", self._path, exc)
            return []

    def _save_locked(self) -> None:
        if self._path is None:
            return
        tmp = self._path.with_suffix(".tmp")
        try:
            payload = {"version": 1, "policies": [p.to_dict() for p in self._items]}
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError as exc:
            log.error("Could not save policies: %s", exc)
