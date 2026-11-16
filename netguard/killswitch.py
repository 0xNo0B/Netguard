"""Kill switch: cut internet for everything except an allow-list.

How: switch every firewall profile's default *outbound* action to Block and add
one allow rule per excepted program. Windows' own built-in allow rules (DNS,
DHCP, core networking) keep the machine itself healthy. The previous defaults
are saved *before* changing anything so they can always be restored, even
after a crash.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .firewall import FirewallBackend, FirewallError, make_rule_id

log = logging.getLogger(__name__)


@dataclass
class KillSwitchState:
    active: bool = False
    previous: dict[str, str] = field(default_factory=dict)
    allowed: dict[str, str] = field(default_factory=dict)  # rule_id -> exe
    since: float = 0.0


class KillSwitch:
    def __init__(self, backend: FirewallBackend, state_path: Path | None,
                 clock: Callable[[], float] = time.time) -> None:
        self._backend = backend
        self._path = state_path
        self._clock = clock
        self._lock = threading.RLock()
        self._state = self._load()

    @property
    def active(self) -> bool:
        with self._lock:
            return self._state.active

    @property
    def since(self) -> float:
        with self._lock:
            return self._state.since

    def enable(self, allowed_exes: list[str]) -> list[str]:
        """Returns non-fatal errors (exceptions that could not be added)."""
        with self._lock:
            if self._state.active:
                return self.update_allowed(allowed_exes)
            previous = self._backend.get_outbound_policy()
            # Persist the original defaults FIRST: a crash after this point
            # can still be undone on next start.
            self._state = KillSwitchState(True, previous, {}, self._clock())
            self._save()
            errors = self._apply_allowed(allowed_exes)
            try:
                self._backend.set_outbound_policy({p: "Block" for p in previous})
            except FirewallError:
                self._rollback()
                raise
            log.info("Kill switch ON (previous=%s)", previous)
            return errors

    def disable(self) -> list[str]:
        with self._lock:
            if not self._state.active:
                return []
            self._backend.set_outbound_policy(self._state.previous)
            errors = self._apply_allowed([])
            self._state = KillSwitchState()
            self._save()
            log.info("Kill switch OFF")
            return errors

    def update_allowed(self, allowed_exes: list[str]) -> list[str]:
        with self._lock:
            if not self._state.active:
                return []
            return self._apply_allowed(allowed_exes)

    def restore(self) -> list[str]:
        """After restart: make the firewall match the saved state."""
        errors: list[str] = []
        with self._lock:
            try:
                live_allow = self._backend.list_allow_ids()
            except FirewallError as exc:
                return [str(exc)]
            if not self._state.active:
                for rule_id in live_allow:  # leftovers
                    try:
                        self._backend.remove_allow(rule_id)
                    except FirewallError as exc:
                        errors.append(str(exc))
                return errors
            for rule_id, exe in self._state.allowed.items():
                if rule_id not in live_allow:
                    try:
                        self._backend.add_allow(rule_id, exe)
                    except FirewallError as exc:
                        errors.append(f"{exe}: {exc}")
            try:
                current = self._backend.get_outbound_policy()
                if any(v != "Block" for v in current.values()):
                    self._backend.set_outbound_policy({p: "Block" for p in current})
            except FirewallError as exc:
                errors.append(str(exc))
        return errors

    # ---- internals ----------------------------------------------------------
    def _apply_allowed(self, allowed_exes: list[str]) -> list[str]:
        wanted = {make_rule_id(exe): exe for exe in allowed_exes if exe}
        errors = []
        for rule_id in list(self._state.allowed):
            if rule_id not in wanted:
                try:
                    self._backend.remove_allow(rule_id)
                    self._state.allowed.pop(rule_id)
                except FirewallError as exc:
                    errors.append(str(exc))
        for rule_id, exe in wanted.items():
            if rule_id not in self._state.allowed:
                try:
                    self._backend.add_allow(rule_id, exe)
                    self._state.allowed[rule_id] = exe
                except FirewallError as exc:
                    errors.append(f"{os.path.basename(exe)}: {exc}")
        self._save()
        return errors

    def _rollback(self) -> None:
        try:
            self._apply_allowed([])
        finally:
            self._state = KillSwitchState()
            self._save()

    def _load(self) -> KillSwitchState:
        if self._path is None or not self._path.exists():
            return KillSwitchState()
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return KillSwitchState(
                active=bool(data.get("active")),
                previous={str(k): str(v) for k, v in data.get("previous", {}).items()},
                allowed={str(k): str(v) for k, v in data.get("allowed", {}).items()},
                since=float(data.get("since", 0.0)),
            )
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            log.error("Corrupt kill-switch state: %s", exc)
            return KillSwitchState()

    def _save(self) -> None:
        if self._path is None:
            return
        tmp = self._path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(self._state.__dict__, indent=2), encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError as exc:
            log.error("Could not save kill-switch state: %s", exc)

