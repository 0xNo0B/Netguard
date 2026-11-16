"""Main application window (normal + advanced modes, AR/EN, dark/light)."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

import psutil
from PySide6.QtCore import QItemSelection, QItemSelectionModel, QModelIndex, Qt, QThread, QTimer, Signal, Slot
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import autostart, i18n
from ..bandwidth import BandwidthTracker
from ..blocker import BlockManager, RestoreReport
from ..config import APP_NAME, APP_VERSION, CRITICAL_PROCESSES, IS_WINDOWS
from ..firewall import FirewallError, make_rule_id
from ..history import HistoryStore
from ..hostnames import HostResolver
from ..i18n import TextBinder, join, ltr, tr
from ..killswitch import KillSwitch
from ..monitor import NetworkMonitor, ProcessGroup, ThroughputMeter
from ..platform_utils import reveal_in_file_manager
from ..policies import PolicyStore
from ..settings import Settings
from . import theme
from .icons import app_icon
from .models import BlockedTableModel, ConnectionsModel, ProcessFilterProxy, ProcessTableModel, format_rate
from .tabs import HistoryTab, KillSwitchTab, RulesTab, SettingsTab, make_table
from .tray import TrayController
from .workers import FirewallWorker, ScanWorker

log = logging.getLogger(__name__)

CUSTOM = "custom"
DURATIONS: list[tuple[str, object]] = [
    ("dur_1m", 60), ("dur_5m", 5 * 60), ("dur_15m", 15 * 60), ("dur_30m", 30 * 60),
    ("dur_1h", 60 * 60), ("dur_3h", 3 * 60 * 60), ("dur_manual", None), ("dur_custom", CUSTOM),
]
DEFAULT_DURATION_INDEX = 2


@dataclass
class Services:
    """Everything the window needs besides the monitor."""
    manager: BlockManager
    settings: Settings
    settings_path: Path | None = None
    policies: PolicyStore | None = None
    killswitch: KillSwitch | None = None
    history: HistoryStore | None = None
    bandwidth: BandwidthTracker | None = None
    resolver: HostResolver | None = None
    data_dir: str = ""


class MainWindow(QMainWindow):
    sig_block = Signal(object, object, bool)
    sig_unblock = Signal(object)
    sig_scan_now = Signal()
    sig_set_interval = Signal(int)
    sig_set_advanced = Signal(bool)
    sig_sync_policies = Signal()
    sig_killswitch = Signal(bool, object)
    sig_allowlist = Signal(object)

    def __init__(self, monitor: NetworkMonitor, meter: ThroughputMeter, services: Services, *,
                 can_block: bool, warnings: list[str] | None = None) -> None:
        super().__init__()
        self.s = services
        self._settings = services.settings
        self._manager = services.manager
        self._can_block = can_block
        self._static_warnings: list[str] = list(warnings or [])  # translation keys
        self._runtime_warnings: list[tuple[str, dict]] = []
        self._pending_ops = 0
        self._killswitch_busy = False
        self._killswitch_active = False
        self.confirm_on_close = True
        self._closing = False
        self._quitting = False
        self._tray_hint_shown = False
        self._t = TextBinder()

        self.setWindowIcon(app_icon())
        self.resize(1360, 860)
        self.setMinimumSize(1000, 640)
        self._build_ui()
        self._build_shortcuts()
        self._start_workers(monitor, meter)

        self._ui_timer = QTimer(self)
        self._ui_timer.timeout.connect(self._refresh_blocked)
        self._ui_timer.start(1000)

        self._apply_mode(initial=True)
        self._retranslate()

    # ------------------------------------------------------------------ UI --
    def _build_ui(self) -> None:
        central = QWidget(objectName="Central")
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 14, 16, 10)
        root.setSpacing(10)

        # Header ---------------------------------------------------------------
        header = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        titles.addWidget(QLabel(APP_NAME, objectName="AppTitle"))
        self.subtitle = QLabel(objectName="Subtitle")
        titles.addWidget(self.subtitle)
        header.addLayout(titles)
        header.addStretch(1)

        segment = QFrame(objectName="Segment")
        seg_layout = QHBoxLayout(segment)
        seg_layout.setContentsMargins(3, 3, 3, 3)
        seg_layout.setSpacing(2)
        self.mode_normal = QPushButton(checkable=True)
        self.mode_advanced = QPushButton(checkable=True)
        seg_layout.addWidget(self.mode_normal)
        seg_layout.addWidget(self.mode_advanced)
        self.lang_btn = QPushButton()
        self.theme_btn = QPushButton()
        self.badge_backend = QLabel(objectName="Badge")
        self.badge_admin = QLabel(objectName="Badge")
        for w in (segment, self.lang_btn, self.theme_btn, self.badge_backend, self.badge_admin):
            header.addWidget(w, 0, Qt.AlignmentFlag.AlignVCenter)
        root.addLayout(header)

        # Kill switch alert (both modes) + warnings banner -------------------
        self.kill_alert = QFrame(objectName="KillAlert")
        ka = QHBoxLayout(self.kill_alert)
        ka.setContentsMargins(12, 8, 12, 8)
        self.kill_alert_label = QLabel()
        self.kill_alert_btn = QPushButton()
        ka.addWidget(self.kill_alert_label, 1)
        ka.addWidget(self.kill_alert_btn)
        self.kill_alert.hide()
        root.addWidget(self.kill_alert)

        self.banner = QLabel(objectName="Banner")
        self.banner.setWordWrap(True)
        self.banner.hide()
        root.addWidget(self.banner)

        # Filter row -----------------------------------------------------------
        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setClearButtonEnabled(True)
        self.only_internet = QCheckBox()
        self.only_internet.setChecked(True)
        self.interval = QSpinBox()
        self.interval.setRange(1, 30)
        self.interval.setValue(self._settings.scan_interval_s)
        self.interval_label = QLabel()
        self.refresh_btn = QPushButton()
        filters.addWidget(self.search, 1)
        filters.addWidget(self.only_internet)
        filters.addSpacing(12)
        filters.addWidget(self.interval_label)
        filters.addWidget(self.interval)
        filters.addWidget(self.refresh_btn)
        root.addLayout(filters)

        # Process table ----------------------------------------------------------
        self.proc_model = ProcessTableModel(self)
        self.proxy = ProcessFilterProxy(self)
        self.proxy.setSourceModel(self.proc_model)
        self.proc_view = make_table(self.proxy)
        self.proc_view.setSortingEnabled(True)
        self.proc_view.sortByColumn(ProcessTableModel.COL_EXT, Qt.SortOrder.DescendingOrder)
        self.proc_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.proc_view.setMinimumHeight(200)
        for col, width in enumerate([75, 190, 95, 95, 300, 100, 80, 70, 55, 110, 230]):
            self.proc_view.setColumnWidth(col, width)

        # Action bar -------------------------------------------------------------
        action_bar = QFrame(objectName="ActionBar")
        actions = QHBoxLayout(action_bar)
        actions.setContentsMargins(12, 8, 12, 8)
        self.selection_label = QLabel(objectName="Subtitle")
        self.duration_label = QLabel()
        self.duration = QComboBox()
        self.kill_check = QCheckBox()
        self.kill_check.setChecked(True)
        self.block_btn = QPushButton(objectName="DangerButton")
        self.unblock_btn = QPushButton(objectName="SuccessButton")
        self.add_rule_btn = QPushButton()
        self.add_allow_btn = QPushButton()
        actions.addWidget(self.selection_label, 1)
        for w in (self.add_rule_btn, self.add_allow_btn, self.duration_label, self.duration, self.kill_check,
                  self.block_btn, self.unblock_btn):
            actions.addWidget(w)

        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(8)
        top_layout.addWidget(self.proc_view, 1)
        top_layout.addWidget(action_bar)

        # Bottom tabs ------------------------------------------------------------
        self.tabs = QTabWidget()
        blocked_page = QWidget()
        bl = QVBoxLayout(blocked_page)
        bl.setContentsMargins(8, 8, 8, 8)
        self.blocked_model = BlockedTableModel(self, policy_names=self._policy_names)
        self.blocked_view = make_table(self.blocked_model)
        for col, width in enumerate([180, 430, 190, 90]):
            self.blocked_view.setColumnWidth(col, width)
        self.blocked_view.doubleClicked.connect(lambda _i: self._unblock_selected_entries())
        blocked_buttons = QHBoxLayout()
        self.blocked_hint = QLabel(objectName="Subtitle")
        self.unblock_entry_btn = QPushButton()
        self.unblock_all_btn = QPushButton()
        blocked_buttons.addWidget(self.blocked_hint, 1)
        blocked_buttons.addWidget(self.unblock_entry_btn)
        blocked_buttons.addWidget(self.unblock_all_btn)
        bl.addWidget(self.blocked_view, 1)
        bl.addLayout(blocked_buttons)

        details_page = QWidget()
        dl = QVBoxLayout(details_page)
        dl.setContentsMargins(8, 8, 8, 8)
        self.details_title = QLabel(objectName="Subtitle")
        self.conn_model = ConnectionsModel(self)
        self.conn_view = make_table(self.conn_model)
        for col, width in enumerate([80, 65, 70, 210, 230, 230, 70]):
            self.conn_view.setColumnWidth(col, width)
        dl.addWidget(self.details_title)
        dl.addWidget(self.conn_view, 1)

        self.rules_tab = RulesTab(self.s.policies or PolicyStore(None), self.selected_groups) \
            if self.s.policies is not None else None
        self.kill_tab = KillSwitchTab(self._settings, self._save_settings, self.selected_groups)
        self.history_tab = HistoryTab(self.s.history)
        self.settings_tab = SettingsTab(self._settings, self.s.data_dir, autostart_supported=IS_WINDOWS)

        self.tabs.addTab(blocked_page, "")
        self.tabs.addTab(details_page, "")
        self._tab_rules = self.tabs.addTab(self.rules_tab or QWidget(), "")
        self._tab_kill = self.tabs.addTab(self.kill_tab, "")
        self._tab_history = self.tabs.addTab(self.history_tab, "")
        self._tab_settings = self.tabs.addTab(self.settings_tab, "")
        self.tabs.currentChanged.connect(self._on_tab_changed)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(top)
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setChildrenCollapsible(False)
        self.tabs.setMinimumHeight(290)
        splitter.setSizes([480, 300])
        root.addWidget(splitter, 1)
        self.setCentralWidget(central)

        # Status bar -----------------------------------------------------------------
        self.lbl_counts = QLabel()
        self.lbl_rates = QLabel()
        self.statusBar().addPermanentWidget(self.lbl_counts)
        self.statusBar().addPermanentWidget(self.lbl_rates)
        self.statusBar().addPermanentWidget(QLabel(f"v{APP_VERSION}"))

        # Tray -------------------------------------------------------------------------
        self.tray = TrayController(self)
        self.tray.show_requested.connect(self.show_from_tray)
        self.tray.quit_requested.connect(self.quit_app)
        self.tray.killswitch_toggled.connect(self.request_killswitch)
        self.tray.unblock_all_requested.connect(self._unblock_all_no_confirm)

        # Static text bindings ---------------------------------------------------------
        t = self._t.bind
        t(self.subtitle.setText, "subtitle")
        t(self.mode_normal.setText, "mode_normal")
        t(self.mode_advanced.setText, "mode_advanced")
        t(self.search.setPlaceholderText, "search_placeholder")
        t(self.only_internet.setText, "only_internet")
        t(self.only_internet.setToolTip, "only_internet_tip")
        t(self.interval_label.setText, "refresh_every")
        t(self.interval.setSuffix, "seconds_suffix")
        t(self.refresh_btn.setText, "refresh_now")
        t(self.duration_label.setText, "duration")
        t(self.kill_check.setText, "kill_existing")
        t(self.kill_check.setToolTip, "kill_existing_tip")
        t(self.block_btn.setText, "block_btn")
        t(self.unblock_btn.setText, "unblock_btn")
        t(self.add_rule_btn.setText, "add_rule_btn")
        t(self.add_allow_btn.setText, "add_allow_btn")
        t(self.add_allow_btn.setToolTip, "add_allow_tip")
        t(self.unblock_entry_btn.setText, "unblock_selected")
        t(self.unblock_all_btn.setText, "unblock_all")
        t(self.kill_alert_label.setText, "killswitch_alert")
        t(self.kill_alert_btn.setText, "killswitch_turn_off")
        t(self.lang_btn.setText, "other_language")
        t(self.lang_btn.setToolTip, "language_tip")

        # Wiring ---------------------------------------------------------------------------
        self.mode_normal.clicked.connect(lambda: self.set_mode("normal"))
        self.mode_advanced.clicked.connect(lambda: self.set_mode("advanced"))
        self.lang_btn.clicked.connect(self.toggle_language)
        self.theme_btn.clicked.connect(self.toggle_theme)
        self.search.textChanged.connect(self.proxy.set_text)
        self.only_internet.toggled.connect(self.proxy.set_only_internet)
        self.interval.valueChanged.connect(self._on_interval_changed)
        self.refresh_btn.clicked.connect(self.sig_scan_now.emit)
        self.proc_view.selectionModel().selectionChanged.connect(lambda *_: self._on_selection_changed())
        self.proc_view.customContextMenuRequested.connect(self._show_context_menu)
        self.proc_view.doubleClicked.connect(lambda _i: self.tabs.setCurrentIndex(1))
        self.block_btn.clicked.connect(self.block_selected)
        self.unblock_btn.clicked.connect(self.unblock_selected_processes)
        self.add_rule_btn.clicked.connect(self._add_rule_for_selection)
        self.add_allow_btn.clicked.connect(lambda: self.kill_tab.add_selected())
        self.unblock_entry_btn.clicked.connect(self._unblock_selected_entries)
        self.unblock_all_btn.clicked.connect(self._unblock_all)
        self.blocked_view.selectionModel().selectionChanged.connect(lambda *_: self._update_buttons())
        self.kill_alert_btn.clicked.connect(lambda: self.request_killswitch(False))
        if self.rules_tab is not None:
            self.rules_tab.policies_changed.connect(self.sig_sync_policies.emit)
            self.rules_tab.policies_changed.connect(self._refresh_blocked)
        self.kill_tab.toggle_requested.connect(self.request_killswitch)
        self.kill_tab.allowlist_changed.connect(self.sig_allowlist.emit)
        self.settings_tab.changed.connect(self._on_setting_changed)

    def _build_shortcuts(self) -> None:
        def add(seq, slot):
            act = QAction(self)
            act.setShortcut(QKeySequence(seq))
            act.triggered.connect(slot)
            self.addAction(act)

        add("Ctrl+F", lambda: (self.search.setFocus(), self.search.selectAll()))
        add("F5", self.sig_scan_now.emit)
        add("Ctrl+B", self.block_selected)
        add("Ctrl+U", self.unblock_selected_processes)
        add("Ctrl+L", self.toggle_language)

    # ------------------------------------------------------------- workers --
    def _start_workers(self, monitor: NetworkMonitor, meter: ThroughputMeter) -> None:
        self._scan_thread = QThread(self)
        self._scan_worker = ScanWorker(monitor, meter, self._settings.scan_interval_s * 1000,
                                       self.s.bandwidth, self.s.resolver, self.s.history)
        self._scan_worker.moveToThread(self._scan_thread)
        self._scan_thread.started.connect(self._scan_worker.start)
        self._scan_thread.finished.connect(self._scan_worker.deleteLater)
        self._scan_worker.snapshot_ready.connect(self._on_snapshot)
        self._scan_worker.scan_failed.connect(self._on_scan_failed)
        self.sig_scan_now.connect(self._scan_worker.scan)
        self.sig_set_interval.connect(self._scan_worker.set_interval)
        self.sig_set_advanced.connect(self._scan_worker.set_advanced)

        self._fw_thread = QThread(self)
        self._fw_worker = FirewallWorker(self._manager, self.s.policies, self.s.killswitch, self.s.history)
        self._fw_worker.moveToThread(self._fw_thread)
        self._fw_thread.started.connect(self._fw_worker.start)
        self._fw_thread.finished.connect(self._fw_worker.deleteLater)
        self._fw_worker.startup_done.connect(self._on_startup_done)
        self._fw_worker.operation_done.connect(self._on_operation_done)
        self._fw_worker.entries_changed.connect(self._on_entries_changed)
        self._fw_worker.expired.connect(self._on_expired)
        self._fw_worker.policy_changes.connect(self._on_policy_changes)
        self._fw_worker.killswitch_changed.connect(self._on_killswitch_changed)
        self.sig_block.connect(self._fw_worker.block)
        self.sig_unblock.connect(self._fw_worker.unblock)
        self.sig_sync_policies.connect(self._fw_worker.sync_policies)
        self.sig_killswitch.connect(self._fw_worker.set_killswitch)
        self.sig_allowlist.connect(self._fw_worker.update_allowlist)

        self._scan_thread.start()
        self._fw_thread.start()

    def shutdown_workers(self) -> None:
        self._ui_timer.stop()
        for thread in (self._scan_thread, self._fw_thread):
            thread.quit()
            if not thread.wait(20000):
                log.warning("Worker thread did not stop in time")
        if self.s.resolver is not None:
            self.s.resolver.shutdown()

    # ------------------------------------------------------- mode / i18n --
    @property
    def advanced(self) -> bool:
        return self._settings.advanced

    def set_mode(self, mode: str) -> None:
        if mode != self._settings.mode:
            self._settings.mode = mode
            self._save_settings()
        self._apply_mode()

    def _apply_mode(self, initial: bool = False) -> None:
        adv = self.advanced
        self.mode_normal.setChecked(not adv)
        self.mode_advanced.setChecked(adv)
        for col in ProcessTableModel.ADVANCED_COLUMNS:
            self.proc_view.setColumnHidden(col, not adv)
        for col in (ConnectionsModel.COL_HOST, ConnectionsModel.COL_COUNTRY):
            self.conn_view.setColumnHidden(col, not adv)
        for index in (self._tab_rules, self._tab_kill, self._tab_history, self._tab_settings):
            self.tabs.setTabVisible(index, adv)
        if self.rules_tab is None:
            self.tabs.setTabVisible(self._tab_rules, False)
        if not adv and self.tabs.currentIndex() > 1:
            self.tabs.setCurrentIndex(0)
        self.theme_btn.setVisible(adv)
        self.add_rule_btn.setVisible(adv and self.rules_tab is not None)
        self.add_allow_btn.setVisible(adv)
        self.blocked_view.setColumnHidden(2, not adv)
        if self.s.resolver is not None:
            self.s.resolver.hostnames_enabled = adv and self._settings.resolve_hostnames
            self.s.resolver.countries_enabled = adv and self._settings.show_countries
        self.sig_set_advanced.emit(adv)
        self._apply_tray()
        self._refresh_banner()
        if not initial:
            self.sig_scan_now.emit()

    def _apply_tray(self) -> None:
        self.tray.set_visible(self.advanced and self._settings.tray_enabled)

    def toggle_language(self) -> None:
        self._settings.language = "en" if i18n.language() == "ar" else "ar"
        self._save_settings()
        i18n.set_language(self._settings.language)
        QApplication.instance().setLayoutDirection(
            Qt.LayoutDirection.RightToLeft if i18n.is_rtl() else Qt.LayoutDirection.LeftToRight)
        self._retranslate()

    def toggle_theme(self) -> None:
        self._settings.theme = "light" if self._settings.theme == "dark" else "dark"
        self._save_settings()
        self._apply_theme()

    def _apply_theme(self) -> None:
        theme.apply_theme(QApplication.instance(), self._settings.theme)
        self.settings_tab.load_values(self.settings_tab.autostart.isChecked())
        self._update_theme_button()
        for model in (self.proc_model, self.blocked_model, self.conn_model):
            model.retranslate()

    def _update_theme_button(self) -> None:
        self.theme_btn.setText(tr("theme_light") if self._settings.theme == "dark" else tr("theme_dark"))

    def _retranslate(self) -> None:
        self.setWindowTitle(f"{APP_NAME} — {tr('window_title')}")
        self._t.apply()
        self._fill_durations()
        self._update_theme_button()
        backend = self._manager.backend
        self.badge_backend.setText(tr("badge_firewall", name=backend.name))
        self.badge_backend.setProperty("ok", not backend.simulated)
        self.badge_admin.setText(tr("badge_admin_ok") if self._can_block else tr("badge_admin_missing"))
        self.badge_admin.setProperty("ok", self._can_block)
        for badge in (self.badge_backend, self.badge_admin):
            badge.style().unpolish(badge)
            badge.style().polish(badge)
        if not self._can_block:
            self.block_btn.setToolTip(tr("needs_admin"))
        for index, key in ((1, "tab_details"), (self._tab_rules, "tab_rules"), (self._tab_kill, "tab_killswitch"),
                           (self._tab_history, "tab_history"), (self._tab_settings, "tab_settings")):
            self.tabs.setTabText(index, tr(key).replace("&", "&&"))  # '&' is a mnemonic in tab bars
        for model in (self.proc_model, self.blocked_model, self.conn_model):
            model.retranslate()
        for tab in (self.rules_tab, self.kill_tab, self.history_tab, self.settings_tab):
            if tab is not None:
                tab.retranslate()
        self.tray.retranslate()
        self._refresh_blocked()
        self._refresh_banner()
        self._on_selection_changed()
        self._update_counts()

    def _fill_durations(self) -> None:
        index = self.duration.currentIndex()
        self.duration.blockSignals(True)
        self.duration.clear()
        for key, value in DURATIONS:
            self.duration.addItem(tr(key), value)
        self.duration.setCurrentIndex(index if index >= 0 else DEFAULT_DURATION_INDEX)
        self.duration.blockSignals(False)

    def _save_settings(self) -> None:
        if self.s.settings_path is not None:
            self._settings.save(self.s.settings_path)

    def _on_interval_changed(self, value: int) -> None:
        self._settings.scan_interval_s = value
        self._save_settings()
        self.sig_set_interval.emit(value * 1000)

    def _on_setting_changed(self, name: str) -> None:
        if name == "autostart":
            wanted = self.settings_tab.autostart.isChecked()
            try:
                autostart.set_enabled(wanted)
            except FirewallError as exc:
                self.settings_tab.set_autostart_checked(not wanted)
                QMessageBox.warning(self, APP_NAME, tr("msg_failed", errors=str(exc)))
            return
        self._save_settings()
        if name == "theme":
            self._apply_theme()
        elif name in ("tray_enabled", "close_to_tray"):
            self._apply_tray()
        elif name in ("resolve_hostnames", "show_countries"):
            self._apply_mode()
        elif name == "history_days" and self.s.history is not None:
            self.s.history.prune(self._settings.history_days)

    # ------------------------------------------------------------ handlers --
    @Slot(object, object)
    def _on_snapshot(self, groups: list[ProcessGroup], rates: tuple[float, float]) -> None:
        if self._closing:
            return
        keys = {g.key for g in self.selected_groups()}
        current = self.proc_view.currentIndex()
        current_key = None
        if current.isValid():
            src = self.proxy.mapToSource(current)
            if src.isValid():
                current_key = self.proc_model.group_at(src.row()).key
        scroll = self.proc_view.verticalScrollBar().value()

        self.proc_model.set_groups(groups, self._manager.blocked_ids())
        self._restore_selection(keys, current_key)
        self.proc_view.verticalScrollBar().setValue(scroll)
        self._groups = groups
        self._rates = rates
        self._update_counts()
        self._on_selection_changed()

    def _update_counts(self) -> None:
        groups = getattr(self, "_groups", [])
        up, down = getattr(self, "_rates", (0.0, 0.0))
        external = sum(g.external_count for g in groups)
        online = sum(1 for g in groups if g.external_count)
        self.lbl_counts.setText(tr("status_counts", online=online, external=external,
                                   blocked=len(self._manager.blocked_ids())))
        self.lbl_rates.setText(ltr(f"↑ {format_rate(up)}    ↓ {format_rate(down)}"))

    def _restore_selection(self, keys: set[str], current_key: str | None) -> None:
        if not keys and current_key is None:
            return
        sm = self.proc_view.selectionModel()
        selection = QItemSelection()
        last_col = self.proxy.columnCount() - 1
        current_index = QModelIndex()
        for row in range(self.proxy.rowCount()):
            key = self.proc_model.group_at(self.proxy.mapToSource(self.proxy.index(row, 0)).row()).key
            if key in keys:
                selection.select(self.proxy.index(row, 0), self.proxy.index(row, last_col))
            if key == current_key:
                current_index = self.proxy.index(row, 0)
        sm.blockSignals(True)
        if current_index.isValid():
            sm.setCurrentIndex(current_index, QItemSelectionModel.SelectionFlag.NoUpdate)
        sm.select(selection, QItemSelectionModel.SelectionFlag.ClearAndSelect)
        sm.blockSignals(False)
        self.proc_view.viewport().update()

    @Slot(str)
    def _on_scan_failed(self, message: str) -> None:
        self.statusBar().showMessage(tr("msg_scan_failed", error=message), 5000)

    @Slot(object, object, object)
    def _on_startup_done(self, report: RestoreReport, status, ks_errors) -> None:
        if status:
            disabled = [name for name, enabled in status.items() if not enabled]
            if disabled:
                self._runtime_warnings.append(("warn_firewall_off", {"profiles": join(disabled)}))
        notes = []
        if report.restored:
            notes.append(tr("msg_restored", names=join(e.name for e in report.restored)))
        if report.expired_removed:
            notes.append(tr("msg_expired_removed", names=join(report.expired_removed)))
        if report.orphans_removed:
            notes.append(tr("msg_orphans_removed", n=len(report.orphans_removed)))
        if notes:
            self.statusBar().showMessage(" — ".join(notes), 10000)
        errors = list(report.errors) + list(ks_errors or [])
        if errors:
            self._runtime_warnings.append(("warn_restore_errors", {"errors": " | ".join(errors)}))
        self._refresh_banner()

    @Slot(bool, str)
    def _on_operation_done(self, ok: bool, message: str) -> None:
        self._pending_ops = max(0, self._pending_ops - 1)
        if not self._pending_ops:
            QApplication.restoreOverrideCursor()
        self.statusBar().showMessage(message, 8000)
        if not ok and not self._closing and self.isVisible():
            QMessageBox.warning(self, APP_NAME, message)
        self._update_buttons()
        self.sig_scan_now.emit()

    @Slot()
    def _on_entries_changed(self) -> None:
        self.proc_model.set_blocked(self._manager.blocked_ids())
        self.proxy.refilter()
        self._refresh_blocked()
        self._update_buttons()
        self._update_counts()

    @Slot(object)
    def _on_expired(self, entries) -> None:
        names = join(e.name for e in entries)
        self.statusBar().showMessage(tr("msg_expired", names=names), 8000)
        self._notify(tr("notify_expired_title"), tr("msg_expired", names=names))

    @Slot(object)
    def _on_policy_changes(self, result) -> None:
        if self.rules_tab is not None:
            self.rules_tab.refresh()
        if result.added:
            self._notify(tr("notify_rule_title"), tr("msg_rule_blocked", names=join(e.name for e in result.added)))
        if result.removed:
            self._notify(tr("notify_rule_title"),
                         tr("msg_rule_released", names=join(e.name for e in result.removed)))

    @Slot(bool, str)
    def _on_killswitch_changed(self, active: bool, message: str) -> None:
        was = self._killswitch_active
        self._killswitch_active = active
        self._killswitch_busy = False
        self.kill_tab.set_busy(False)
        since = self.s.killswitch.since if self.s.killswitch is not None else 0.0
        self.kill_tab.set_active(active, since)
        self.kill_alert.setVisible(active)
        self.tray.set_killswitch(active)
        if message:
            QMessageBox.warning(self, APP_NAME, message)
        elif was != active:
            self.statusBar().showMessage(tr("killswitch_alert") if active else tr("msg_killswitch_off"), 6000)
            self._notify(tr("killswitch"), tr("killswitch_alert") if active else tr("msg_killswitch_off"))

    def request_killswitch(self, enable: bool) -> None:
        if self.s.killswitch is None or self._killswitch_busy:
            return
        if enable == self._killswitch_active:
            self.tray.set_killswitch(self._killswitch_active)
            return
        if enable:
            if not self._can_block:
                QMessageBox.information(self, APP_NAME, tr("needs_admin"))
                self.tray.set_killswitch(False)
                return
            allowed = self._settings.kill_switch_allow
            names = join(Path(p.replace("\\", "/")).name for p in allowed) or tr("nothing")
            if QMessageBox.warning(
                self, APP_NAME, tr("confirm_killswitch", names=names),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No,
            ) != QMessageBox.StandardButton.Yes:
                self.tray.set_killswitch(False)
                return
        self._killswitch_busy = True
        self.kill_tab.set_busy(True)
        self.sig_killswitch.emit(enable, list(self._settings.kill_switch_allow))

    def _notify(self, title: str, message: str) -> None:
        if self.advanced and self._settings.notifications:
            self.tray.notify(title, message)

    def _policy_names(self, ids: list[str]) -> list[str]:
        return self.rules_tab.policy_names(ids) if self.rules_tab is not None else []

    def _on_tab_changed(self, index: int) -> None:
        if index == self._tab_history:
            self.history_tab.refresh()
        elif index == self._tab_settings:
            self.settings_tab.set_autostart_checked(autostart.is_enabled() if IS_WINDOWS else False)

    def _refresh_blocked(self) -> None:
        entries = self._manager.entries()
        self.blocked_model.update_entries(entries, time.time())
        self.tabs.setTabText(0, tr("tab_blocked", n=len(entries)))
        self.blocked_hint.setText(tr("no_blocked") if not entries else tr("blocked_hint"))

    def _on_selection_changed(self) -> None:
        groups = self.selected_groups()
        if not groups:
            self.selection_label.setText(tr("nothing_selected"))
            self.details_title.setText(tr("details_placeholder"))
            self.conn_model.set_connections([])
        else:
            g = groups[0]
            if len(groups) == 1:
                self.selection_label.setText(tr("selected_one", name=g.name, n=len(g.pids)))
            else:
                self.selection_label.setText(tr("selected_many", n=len(groups)))
            self.details_title.setText(tr("details_title", name=g.name, sockets=len(g.connections),
                                          external=g.external_count))
            self.conn_model.set_connections(g.connections, g.remote_info)
        self._update_buttons()

    def _update_buttons(self) -> None:
        groups = self.selected_groups()
        blocked = self._manager.blocked_ids()
        busy = self._pending_ops > 0
        self.block_btn.setEnabled(self._can_block and not busy and any(g.blockable for g in groups))
        self.unblock_btn.setEnabled(not busy and any(self._rule_id(g) in blocked for g in groups))
        self.add_rule_btn.setEnabled(any(g.blockable for g in groups))
        self.add_allow_btn.setEnabled(any(g.blockable for g in groups))
        self.unblock_entry_btn.setEnabled(not busy and self.blocked_view.selectionModel().hasSelection())
        self.unblock_all_btn.setEnabled(not busy and bool(blocked))

    def _refresh_banner(self) -> None:
        lines = [tr(key) for key in self._static_warnings]  # translation keys
        lines += [tr(key, **fmt) for key, fmt in self._runtime_warnings]
        if self.advanced and self.s.bandwidth is not None and not self.s.bandwidth.available and IS_WINDOWS:
            lines.append(tr("warn_bandwidth_unavailable"))
        if lines:
            self.banner.setText("\n".join(f"⚠  {w}" for w in lines))
            self.banner.show()
        else:
            self.banner.hide()

    def set_static_warnings(self, warnings: list[str]) -> None:
        self._static_warnings = list(warnings)
        self._refresh_banner()

    # ------------------------------------------------------------- actions --
    def selected_groups(self) -> list[ProcessGroup]:
        groups = []
        for index in self.proc_view.selectionModel().selectedRows():
            src = self.proxy.mapToSource(index)
            if src.isValid():
                groups.append(self.proc_model.group_at(src.row()))
        return groups

    @staticmethod
    def _rule_id(group: ProcessGroup) -> str | None:
        return make_rule_id(group.exe) if group.exe else None

    def _choose_duration(self) -> tuple[bool, float | None]:
        value = self.duration.currentData()
        if value == CUSTOM:
            minutes, ok = QInputDialog.getInt(self, APP_NAME, tr("custom_minutes"), 10, 1, 7 * 24 * 60)
            return ok, float(minutes * 60)
        return True, (None if value is None else float(value))

    def _begin_op(self) -> None:
        if not self._pending_ops:
            QApplication.setOverrideCursor(Qt.CursorShape.BusyCursor)
        self._pending_ops += 1
        self.statusBar().showMessage(tr("msg_applying"))
        self._update_buttons()

    @Slot()
    def block_selected(self) -> None:
        if not self._can_block:
            return
        groups = self.selected_groups()
        targets = [g for g in groups if g.blockable]
        skipped = [g.name for g in groups if not g.blockable]
        if not targets:
            if groups:
                QMessageBox.information(self, APP_NAME, tr("cannot_block_protected"))
            return
        critical = sorted({g.name for g in targets if g.name.lower() in CRITICAL_PROCESSES})
        if critical and QMessageBox.warning(
            self, APP_NAME, tr("confirm_critical", names=join(critical)),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        ok, duration = self._choose_duration()
        if not ok:
            return
        if skipped:
            self.statusBar().showMessage(tr("msg_skipped", names=join(skipped)), 6000)
        self._begin_op()
        self.sig_block.emit([(g.exe, g.name, sorted(g.pids), g.package_sid) for g in targets], duration,
                            self.kill_check.isChecked())

    @Slot()
    def unblock_selected_processes(self) -> None:
        blocked = self._manager.blocked_ids()
        ids = [rid for rid in (self._rule_id(g) for g in self.selected_groups()) if rid in blocked]
        if ids:
            self._begin_op()
            self.sig_unblock.emit(ids)

    def _unblock_selected_entries(self) -> None:
        rows = self.blocked_view.selectionModel().selectedRows()
        ids = [self.blocked_model.entry_at(i.row()).rule_id for i in rows]
        if ids:
            self._begin_op()
            self.sig_unblock.emit(ids)

    def _unblock_all(self) -> None:
        entries = self._manager.entries()
        if entries and QMessageBox.question(self, APP_NAME, tr("confirm_unblock_all", n=len(entries))) \
                == QMessageBox.StandardButton.Yes:
            self._unblock_all_no_confirm()

    def _unblock_all_no_confirm(self) -> None:
        entries = self._manager.entries()
        if entries:
            self._begin_op()
            self.sig_unblock.emit([e.rule_id for e in entries])

    def _add_rule_for_selection(self) -> None:
        if self.rules_tab is not None:
            self.rules_tab.add_for_selection()
            self.tabs.setCurrentIndex(self._tab_rules)

    def _show_context_menu(self, pos) -> None:
        if not self.proc_view.indexAt(pos).isValid():
            return
        groups = self.selected_groups()
        if not groups:
            return
        blocked = self._manager.blocked_ids()
        first = groups[0]
        menu = QMenu(self)

        def item(key, slot, enabled=True):
            act = menu.addAction(tr(key))
            act.setEnabled(enabled)
            act.triggered.connect(slot)

        item("block_btn", self.block_selected, self.block_btn.isEnabled())
        item("unblock_btn", self.unblock_selected_processes, any(self._rule_id(g) in blocked for g in groups))
        if self.advanced:
            menu.addSeparator()
            item("add_rule_btn", self._add_rule_for_selection, first.blockable and self.rules_tab is not None)
            item("add_allow_btn", self.kill_tab.add_selected, first.blockable)
        menu.addSeparator()
        item("show_connections", lambda: self.tabs.setCurrentIndex(1))
        item("open_location", lambda: reveal_in_file_manager(first.exe), bool(first.exe))
        item("copy_path", lambda: QGuiApplication.clipboard().setText(first.exe), bool(first.exe))
        menu.addSeparator()
        item("terminate", lambda: self._terminate(groups))
        menu.exec(self.proc_view.viewport().mapToGlobal(pos))

    def _terminate(self, groups: list[ProcessGroup]) -> None:
        if QMessageBox.warning(
            self, APP_NAME, tr("confirm_terminate", names=join(g.name for g in groups)),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        errors = []
        for g in groups:
            for pid in g.pids:
                try:
                    psutil.Process(pid).terminate()
                except psutil.NoSuchProcess:
                    pass
                except (psutil.AccessDenied, OSError) as exc:
                    errors.append(f"{g.name} ({pid}): {exc}")
        if errors:
            QMessageBox.warning(self, APP_NAME, tr("msg_terminate_failed") + "\n" + "\n".join(errors))
        self.sig_scan_now.emit()

    # ------------------------------------------------------------- tray / close --
    def show_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def quit_app(self) -> None:
        self._quitting = True
        self.show_from_tray()
        self.close()

    def _hide_to_tray(self) -> bool:
        return (self.advanced and self._settings.tray_enabled and self._settings.close_to_tray
                and self.tray.visible and not self._quitting)

    def closeEvent(self, event) -> None:
        if self._hide_to_tray():
            event.ignore()
            self.hide()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self.tray.notify(APP_NAME, tr("msg_still_running"))
            return

        remove = True
        entries = self._manager.entries()
        if self.confirm_on_close and (entries or self._killswitch_active):
            box = QMessageBox(self)
            box.setWindowTitle(APP_NAME)
            box.setIcon(QMessageBox.Icon.Question)
            box.setText(tr("close_question", n=len(entries)) if entries else tr("close_question_ks"))
            box.setInformativeText(tr("close_info"))
            remove_btn = box.addButton(tr("close_remove"), QMessageBox.ButtonRole.AcceptRole)
            keep_btn = box.addButton(tr("close_keep"), QMessageBox.ButtonRole.DestructiveRole)
            box.addButton(tr("cancel"), QMessageBox.ButtonRole.RejectRole)
            box.setDefaultButton(remove_btn)
            box.exec()
            clicked = box.clickedButton()
            if clicked not in (remove_btn, keep_btn):
                self._quitting = False
                event.ignore()
                return
            remove = clicked is remove_btn

        self._closing = True
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        errors: list[str] = []
        try:
            self.shutdown_workers()
            if remove:
                errors += self._manager.remove_all()
                if self.s.killswitch is not None and self.s.killswitch.active:
                    try:
                        errors += self.s.killswitch.disable()
                    except FirewallError as exc:
                        errors.append(str(exc))
        finally:
            QApplication.restoreOverrideCursor()
        if errors:
            QMessageBox.warning(self, APP_NAME, tr("msg_cleanup_failed") + "\n" + "\n".join(errors))
        self.tray.set_visible(False)
        event.accept()
        QApplication.instance().quit()
