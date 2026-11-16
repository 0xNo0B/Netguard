"""Block bookkeeping: manual timed blocks + rule-driven (policy) blocks,
expiry, crash-safe persistence.

A program's firewall rules exist while *any* reason applies:
  * manual  — the user pressed "block" (optionally with an expiry), or
  * policies — one or more permanent / scheduled rules are active now.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Callable

from .firewall import FirewallBackend, FirewallError, make_rule_id

log = logging.getLogger(__name__)

RETRY_DELAY_S = 30.0


@dataclass
class BlockEntry:
    rule_id: str
    exe: str
    name: str
    created_at: float
    expires_at: float | None  # manual expiry; None = until removed
    manual: bool = True
    policies: list[str] = field(default_factory=list)  # ids of active rules
    package_sid: str = ""

    def remaining(self, now: float) -> float | None:
        if not self.manual or self.expires_at is None:
            return None
        return max(0.0, self.expires_at - now)

    def is_expired(self, now: float) -> bool:
        return self.manual and self.expires_at is not None and now >= self.expires_at

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "BlockEntry":
        expires = data.get("expires_at")
        return cls(
            rule_id=str(data["rule_id"]),
            exe=str(data["exe"]),
            name=str(data.get("name") or os.path.basename(str(data["exe"]))),
            created_at=float(data.get("created_at", 0.0)),
            expires_at=None if expires is None else float(expires),
            manual=bool(data.get("manual", True)),
            policies=[str(p) for p in data.get("policies", [])],
            package_sid=str(data.get("package_sid", "")),
        )


@dataclass
class UnblockResult:
    entry: BlockEntry
    still_blocked: bool  # a rule (policy) keeps it blocked


@dataclass
class SyncResult:
    added: list[BlockEntry] = field(default_factory=list)
    removed: list[BlockEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class RestoreReport:
    restored: list[BlockEntry] = field(default_factory=list)
    expired_removed: list[str] = field(default_factory=list)
    orphans_removed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DesiredBlock:
    exe: str
    name: str
    package_sid: str
    policy_ids: tuple[str, ...]


class BlockManager:
    """Thread-safe. Firewall calls are serialized by `_op_lock`; `_lock` only
    guards the in-memory dict so the UI can read it without waiting on netsh."""

    def __init__(
        self,
        backend: FirewallBackend,
        state_path: Path | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._backend = backend
        self._path = state_path
        self._clock = clock
        self._lock = threading.RLock()
        self._op_lock = threading.RLock()
        self._entries: dict[str, BlockEntry] = {}
        self._retry_after: dict[str, float] = {}

    @property
    def backend(self) -> FirewallBackend:
        return self._backend

    # ---- queries ------------------------------------------------------------
    def entries(self) -> list[BlockEntry]:
        with self._lock:
            return sorted(
                (replace(e, policies=list(e.policies)) for e in self._entries.values()),
                key=lambda e: e.created_at,
            )

    def blocked_ids(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._entries)

    def is_blocked_exe(self, exe: str) -> bool:
        return bool(exe) and make_rule_id(exe) in self.blocked_ids()

    # ---- manual operations --------------------------------------------------
    def block(self, exe: str, name: str, duration: float | None, package_sid: str = "") -> BlockEntry:
        if not exe:
            raise FirewallError("cannot block a process without an executable path")
        if duration is not None and duration <= 0:
            raise ValueError("duration must be positive or None")
        rule_id = make_rule_id(exe)
        with self._op_lock:
            now = self._clock()
            expires = None if duration is None else now + duration
            with self._lock:
                existing = self._entries.get(rule_id)
                if existing is not None:  # already blocked: (re)set the manual timer
                    existing.manual = True
                    existing.expires_at = expires
                    self._save_locked()
                    return replace(existing)
            self._backend.add_block(rule_id, exe, package_sid)
            entry = BlockEntry(rule_id, exe, name, now, expires, True, [], package_sid)
            with self._lock:
                self._entries[rule_id] = entry
                self._save_locked()
            return replace(entry)

    def unblock(self, rule_id: str) -> UnblockResult:
        """Remove the manual block. If a rule still applies, the program stays blocked."""
        with self._op_lock:
            with self._lock:
                entry = self._entries.get(rule_id)
                if entry is None:
                    raise KeyError(rule_id)
                if entry.policies:
                    entry.manual = False
                    entry.expires_at = None
                    self._save_locked()
                    return UnblockResult(replace(entry), True)
            self._remove(rule_id)
            return UnblockResult(entry, False)

    def remove_all(self) -> list[str]:
        """Drop every firewall rule regardless of reason (used on exit)."""
        errors = []
        with self._op_lock:
            for entry in self.entries():
                try:
                    self._remove(entry.rule_id)
                except FirewallError as exc:
                    errors.append(f"{entry.name}: {exc}")
        return errors

    def _remove(self, rule_id: str) -> None:
        self._backend.remove_block(rule_id)
        with self._lock:
            self._entries.pop(rule_id, None)
            self._retry_after.pop(rule_id, None)
            self._save_locked()

    def expire_due(self) -> list[BlockEntry]:
        now = self._clock()
        with self._lock:
            due = [
                e.rule_id for e in self._entries.values()
                if e.is_expired(now) and self._retry_after.get(e.rule_id, 0.0) <= now
            ]
        expired = []
        for rule_id in due:
            try:
                result = self.unblock(rule_id)
            except KeyError:
                continue
            except FirewallError as exc:
                log.warning("Auto-unblock of %s failed, retrying later: %s", rule_id, exc)
                with self._lock:
                    self._retry_after[rule_id] = now + RETRY_DELAY_S
                continue
            if not result.still_blocked:
                expired.append(result.entry)
        return expired

    # ---- rule-driven blocks -----------------------------------------------
    def sync_policies(self, desired: dict[str, DesiredBlock]) -> SyncResult:
        """Make policy-driven blocks match `desired` (rule_id -> DesiredBlock)."""
        result = SyncResult()
        with self._op_lock:
            now = self._clock()
            for rule_id, want in desired.items():
                with self._lock:
                    entry = self._entries.get(rule_id)
                    if entry is not None:
                        if list(want.policy_ids) != entry.policies:
                            entry.policies = list(want.policy_ids)
                            self._save_locked()
                        continue
                try:
                    self._backend.add_block(rule_id, want.exe, want.package_sid)
                except FirewallError as exc:
                    result.errors.append(f"{want.name}: {exc}")
                    continue
                entry = BlockEntry(rule_id, want.exe, want.name, now, None, False,
                                   list(want.policy_ids), want.package_sid)
                with self._lock:
                    self._entries[rule_id] = entry
                    self._save_locked()
                result.added.append(replace(entry))

            with self._lock:
                stale = [e for e in self._entries.values() if e.rule_id not in desired and e.policies]
            for entry in stale:
                with self._lock:
                    entry.policies = []
                    self._save_locked()
                if not entry.manual:
                    try:
                        self._remove(entry.rule_id)
                        result.removed.append(entry)
                    except FirewallError as exc:
                        result.errors.append(f"{entry.name}: {exc}")
        return result

    # ---- startup ------------------------------------------------------------
    def restore(self) -> RestoreReport:
        """Reconcile saved state with the real firewall after (re)start."""
        report = RestoreReport()
        now = self._clock()
        kept: dict[str, BlockEntry] = {}
        with self._op_lock:
            for entry in self._load():
                if entry.is_expired(now):
                    if entry.policies:  # rule still owns it; drop the manual part
                        entry.manual, entry.expires_at = False, None
                    else:
                        try:
                            self._backend.remove_block(entry.rule_id)
                            report.expired_removed.append(entry.name)
                            continue
                        except FirewallError as exc:
                            report.errors.append(f"{entry.name}: {exc}")
                kept[entry.rule_id] = entry

            try:
                live = self._backend.list_rule_ids()
            except FirewallError as exc:
                report.errors.append(f"firewall rules unreadable: {exc}")
                live = None

            if live is not None:
                for rule_id in sorted(live - kept.keys()):  # rules with no owner
                    try:
                        self._backend.remove_block(rule_id)
                        report.orphans_removed.append(rule_id)
                    except FirewallError as exc:
                        report.errors.append(f"{rule_id}: {exc}")
                for rule_id, entry in list(kept.items()):  # saved but missing
                    if rule_id not in live and not entry.is_expired(now):
                        try:
                            self._backend.add_block(rule_id, entry.exe, entry.package_sid)
                        except FirewallError as exc:
                            report.errors.append(f"{entry.name}: {exc}")
                            kept.pop(rule_id)

            with self._lock:
                self._entries = kept
                self._save_locked()
        report.restored = self.entries()
        return report

    # ---- persistence --------------------------------------------------------
    def _load(self) -> list[BlockEntry]:
        if self._path is None or not self._path.exists():
            return []
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return [BlockEntry.from_dict(item) for item in data.get("blocks", [])]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log.error("Corrupt state file %s: %s", self._path, exc)
            return []

    def _save_locked(self) -> None:
        if self._path is None:
            return
        payload = {"version": 2, "blocks": [e.to_dict() for e in self._entries.values()]}
        tmp = self._path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError as exc:
            log.error("Could not save state: %s", exc)
