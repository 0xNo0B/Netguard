"""Background workers so scanning and firewall calls never freeze the UI."""
from __future__ import annotations

import datetime as dt
import logging

from PySide6.QtCore import QObject, QTimer, Signal, Slot

from ..bandwidth import BandwidthTracker
from ..blocker import BlockManager
from ..config import POLICY_SYNC_INTERVAL_S
from ..firewall import FirewallError
from ..history import HistoryStore
from ..hostnames import HostResolver
from ..i18n import join, tr
from ..killswitch import KillSwitch
from ..monitor import NetworkMonitor, ThroughputMeter
from ..policies import PolicyStore, desired_blocks
from ..tcp_killer import close_tcp_connections

log = logging.getLogger(__name__)


class ScanWorker(QObject):
    snapshot_ready = Signal(object, object)  # list[ProcessGroup], (up_bps, down_bps)
    scan_failed = Signal(str)

    def __init__(self, monitor: NetworkMonitor, meter: ThroughputMeter, interval_ms: int,
                 bandwidth: BandwidthTracker | None = None, resolver: HostResolver | None = None,
                 history: HistoryStore | None = None) -> None:
        super().__init__()
        self._monitor = monitor
        self._meter = meter
        self._interval = interval_ms
        self._bandwidth = bandwidth
        self._resolver = resolver
        self._history = history
        self._advanced = False
        self._timer: QTimer | None = None

    @Slot()
    def start(self) -> None:
        self._timer = QTimer(self)  # created inside the worker thread
        self._timer.timeout.connect(self.scan)
        self._timer.start(self._interval)
        self.scan()

    @Slot(bool)
    def set_advanced(self, enabled: bool) -> None:
        self._advanced = enabled
        if not enabled and self._bandwidth is not None:
            self._bandwidth.reset()

    @Slot()
    def scan(self) -> None:
        try:
            groups = self._monitor.snapshot()
            rates = self._meter.sample()
            if self._advanced:
                if self._bandwidth is not None:
                    self._bandwidth.update(groups)
                    if self._history is not None:
                        self._history.add_usage([
                            (g.key, g.name, g.exe, g.bytes_down, g.bytes_up)
                            for g in groups if g.bytes_down or g.bytes_up
                        ])
                if self._resolver is not None:
                    for g in groups:
                        g.remote_info = {ip: self._resolver.lookup(ip) for ip in g.remote_ips}
        except Exception as exc:  # keep the worker alive whatever happens
            log.exception("Scan failed")
            self.scan_failed.emit(str(exc))
            return
        self.snapshot_ready.emit(groups, rates)

    @Slot(int)
    def set_interval(self, interval_ms: int) -> None:
        self._interval = max(500, interval_ms)
        if self._timer is not None:
            self._timer.start(self._interval)


class FirewallWorker(QObject):
    startup_done = Signal(object, object, object)  # RestoreReport, status|None, kill-switch errors
    operation_done = Signal(bool, str)
    entries_changed = Signal()
    expired = Signal(object)  # list[BlockEntry]
    policy_changes = Signal(object)  # SyncResult
    killswitch_changed = Signal(bool, str)  # active, message ("" = ok)

    def __init__(self, manager: BlockManager, policies: PolicyStore | None = None,
                 killswitch: KillSwitch | None = None, history: HistoryStore | None = None,
                 killer=close_tcp_connections) -> None:
        super().__init__()
        self._manager = manager
        self._policies = policies
        self._killswitch = killswitch
        self._history = history
        self._killer = killer
        self._timer: QTimer | None = None
        self._ticks = 0

    def _log(self, kind: str, name: str = "", exe: str = "", detail: str = "") -> None:
        if self._history is not None:
            self._history.log_event(kind, name, exe, detail)

    @Slot()
    def start(self) -> None:
        report = self._manager.restore()
        ks_errors = self._killswitch.restore() if self._killswitch is not None else []
        status = self._manager.backend.firewall_status()
        self.startup_done.emit(report, status, ks_errors)
        self.sync_policies()
        self.entries_changed.emit()
        if self._killswitch is not None:
            self.killswitch_changed.emit(self._killswitch.active, "")
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)

    @Slot()
    def _tick(self) -> None:
        self._ticks += 1
        entries = self._manager.expire_due()
        if entries:
            for e in entries:
                self._log("expire", e.name, e.exe)
            self.entries_changed.emit()
            self.expired.emit(entries)
        if self._ticks % POLICY_SYNC_INTERVAL_S == 0:
            self.sync_policies()

    @Slot()
    def sync_policies(self) -> None:
        if self._policies is None:
            return
        result = self._manager.sync_policies(desired_blocks(self._policies.all(), dt.datetime.now()))
        for e in result.added:
            self._log("rule_on", e.name, e.exe)
        for e in result.removed:
            self._log("rule_off", e.name, e.exe)
        if result.errors:
            log.warning("Policy sync errors: %s", result.errors)
        if result.added or result.removed or result.errors:
            self.entries_changed.emit()
            self.policy_changes.emit(result)

    @Slot(object, object, bool)
    def block(self, targets, duration, kill_connections: bool) -> None:
        """targets: list of (exe, name, pids, package_sid)."""
        done, errors, closed = [], [], 0
        for exe, name, pids, package_sid in targets:
            try:
                self._manager.block(exe, name, duration, package_sid)
                done.append(name)
                self._log("block", name, exe, "" if duration is None else f"{int(duration // 60)}m")
                if kill_connections:
                    closed += self._killer(pids)[0]
            except (FirewallError, ValueError, OSError) as exc:
                log.warning("Block failed for %s: %s", exe, exc)
                errors.append(f"{name}: {exc}")
        self.entries_changed.emit()
        parts = []
        if done:
            parts.append(tr("msg_blocked", names=join(done)))
        if closed:
            parts.append(tr("msg_closed_conns", n=closed))
        if errors:
            parts.append(tr("msg_failed", errors=" | ".join(errors)))
        self.operation_done.emit(not errors, " — ".join(parts) or tr("msg_nothing"))

    @Slot(object)
    def unblock(self, rule_ids) -> None:
        done, held, errors = [], [], []
        for rule_id in rule_ids:
            try:
                result = self._manager.unblock(rule_id)
            except KeyError:
                continue
            except FirewallError as exc:
                errors.append(str(exc))
                continue
            if result.still_blocked:
                held.append(result.entry.name)
            else:
                done.append(result.entry.name)
                self._log("unblock", result.entry.name, result.entry.exe)
        self.entries_changed.emit()
        parts = []
        if done:
            parts.append(tr("msg_unblocked", names=join(done)))
        if held:
            parts.append(tr("msg_held_by_rule", names=join(held)))
        if errors:
            parts.append(tr("msg_failed", errors=" | ".join(errors)))
        self.operation_done.emit(not errors, " — ".join(parts) or tr("msg_nothing"))

    @Slot(bool, object)
    def set_killswitch(self, enable: bool, allowed) -> None:
        if self._killswitch is None:
            return
        try:
            errors = self._killswitch.enable(list(allowed)) if enable else self._killswitch.disable()
        except FirewallError as exc:
            self.killswitch_changed.emit(self._killswitch.active, tr("msg_failed", errors=str(exc)))
            return
        self._log("killswitch_on" if enable else "killswitch_off")
        message = tr("msg_failed", errors=" | ".join(errors)) if errors else ""
        self.killswitch_changed.emit(self._killswitch.active, message)

    @Slot(object)
    def update_allowlist(self, allowed) -> None:
        if self._killswitch is None or not self._killswitch.active:
            return
        errors = self._killswitch.update_allowed(list(allowed))
        if errors:
            self.killswitch_changed.emit(True, tr("msg_failed", errors=" | ".join(errors)))
