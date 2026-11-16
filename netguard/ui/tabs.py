"""Advanced-mode tabs: rules, kill switch, history, settings."""
from __future__ import annotations

import datetime as dt
import os

from PySide6.QtCore import Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ..config import APP_NAME, normalize_exe
from ..history import HistoryStore
from ..i18n import TextBinder, tr
from ..policies import Policy, PolicyStore
from ..settings import Settings
from .dialogs import PolicyDialog
from .models import AllowListModel, EventsModel, PoliciesModel, UsageModel


def make_table(model, *, multi: bool = True) -> QTableView:
    view = QTableView()
    view.setModel(model)
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.setSelectionMode(
        QAbstractItemView.SelectionMode.ExtendedSelection if multi else QAbstractItemView.SelectionMode.SingleSelection
    )
    view.setAlternatingRowColors(True)
    view.setShowGrid(False)
    view.setWordWrap(False)
    view.verticalHeader().setVisible(False)
    view.verticalHeader().setDefaultSectionSize(32)
    view.horizontalHeader().setHighlightSections(False)
    view.horizontalHeader().setStretchLastSection(True)
    view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    return view


def pick_exe(parent) -> str:
    path, _ = QFileDialog.getOpenFileName(parent, tr("choose_program"), "", tr("exe_filter"))
    return os.path.normpath(path) if path else ""


class RulesTab(QWidget):
    policies_changed = Signal()

    def __init__(self, store: PolicyStore, selection_provider, parent=None) -> None:
        super().__init__(parent)
        self._store = store
        self._selection = selection_provider
        self._t = TextBinder()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        hint = QLabel(objectName="Hint")
        hint.setWordWrap(True)
        self._t.bind(hint.setText, "rules_hint")
        layout.addWidget(hint)
        self.model = PoliciesModel(self)
        self.view = make_table(self.model, multi=False)
        for col, width in enumerate([200, 90, 260, 140, 70]):
            self.view.setColumnWidth(col, width)
        self.view.doubleClicked.connect(lambda _i: self.edit_selected())
        layout.addWidget(self.view, 1)
        row = QHBoxLayout()
        self.add_sel_btn = QPushButton()
        self.add_file_btn = QPushButton()
        self.edit_btn = QPushButton()
        self.toggle_btn = QPushButton()
        self.delete_btn = QPushButton()
        for btn, key in ((self.add_sel_btn, "rule_add_selected"), (self.add_file_btn, "rule_add_file"),
                         (self.edit_btn, "edit"), (self.toggle_btn, "rule_toggle"), (self.delete_btn, "delete")):
            self._t.bind(btn.setText, key)
            row.addWidget(btn)
        row.insertStretch(2, 1)
        layout.addLayout(row)
        self.add_sel_btn.clicked.connect(self.add_for_selection)
        self.add_file_btn.clicked.connect(self.add_from_file)
        self.edit_btn.clicked.connect(self.edit_selected)
        self.toggle_btn.clicked.connect(self.toggle_selected)
        self.delete_btn.clicked.connect(self.delete_selected)
        self.view.selectionModel().selectionChanged.connect(lambda *_: self._update_buttons())
        self.refresh()

    def retranslate(self) -> None:
        self._t.apply()
        self.model.retranslate()

    def refresh(self) -> None:
        selected = self._current()
        self.model.set_policies(self._store.all())
        if selected is not None:
            for row in range(self.model.rowCount()):
                if self.model.policy_at(row).id == selected.id:
                    self.view.selectRow(row)
        self._update_buttons()

    def policy_names(self, ids: list[str]) -> list[str]:
        names = []
        for pid in ids:
            p = self._store.get(pid)
            if p is not None:
                names.append(tr("kind_always") if p.kind == "always" else tr("kind_schedule"))
        return names

    def _current(self) -> Policy | None:
        rows = self.view.selectionModel().selectedRows() if self.view.selectionModel() else []
        return self.model.policy_at(rows[0].row()) if rows else None

    def _update_buttons(self) -> None:
        has = self._current() is not None
        for btn in (self.edit_btn, self.toggle_btn, self.delete_btn):
            btn.setEnabled(has)

    def _edit(self, policy: Policy) -> None:
        dialog = PolicyDialog(policy, self)
        if dialog.exec():
            self._store.upsert(dialog.result_policy())
            self.refresh()
            self.policies_changed.emit()

    def add_for_selection(self) -> None:
        groups = [g for g in self._selection() if g.blockable]
        if not groups:
            QMessageBox.information(self, APP_NAME, tr("select_program_first"))
            return
        g = groups[0]
        self._edit(Policy(exe=g.exe, name=g.name, package_sid=g.package_sid))

    def add_from_file(self) -> None:
        path = pick_exe(self)
        if path:
            self._edit(Policy(exe=path, name=os.path.basename(path)))

    def edit_selected(self) -> None:
        policy = self._current()
        if policy is not None:
            self._edit(policy)

    def toggle_selected(self) -> None:
        policy = self._current()
        if policy is not None:
            self._store.set_enabled(policy.id, not policy.enabled)
            self.refresh()
            self.policies_changed.emit()

    def delete_selected(self) -> None:
        policy = self._current()
        if policy is None:
            return
        if QMessageBox.question(self, APP_NAME, tr("confirm_delete_rule", name=policy.name)) \
                == QMessageBox.StandardButton.Yes:
            self._store.delete(policy.id)
            self.refresh()
            self.policies_changed.emit()


class KillSwitchTab(QWidget):
    toggle_requested = Signal(bool)
    allowlist_changed = Signal(object)

    def __init__(self, settings: Settings, save_settings, selection_provider, parent=None) -> None:
        super().__init__(parent)
        self._settings = settings
        self._save = save_settings
        self._selection = selection_provider
        self._active = False
        self._since = 0.0
        self._t = TextBinder()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        top = QHBoxLayout()
        self.status = QLabel(objectName="BigStatus")
        self.toggle_btn = QPushButton(objectName="DangerButton")
        self.toggle_btn.setMinimumWidth(220)
        top.addWidget(self.status, 1)
        top.addWidget(self.toggle_btn)
        layout.addLayout(top)
        hint = QLabel(objectName="Hint")
        hint.setWordWrap(True)
        self._t.bind(hint.setText, "killswitch_hint")
        layout.addWidget(hint)
        title = QLabel(objectName="SectionTitle")
        self._t.bind(title.setText, "allowlist_title")
        layout.addWidget(title)
        self.model = AllowListModel(self)
        self.view = make_table(self.model)
        self.view.setColumnWidth(0, 200)
        self.view.setMinimumHeight(72)
        layout.addWidget(self.view, 1)
        row = QHBoxLayout()
        self.add_sel_btn = QPushButton()
        self.add_file_btn = QPushButton()
        self.remove_btn = QPushButton()
        self._t.bind(self.add_sel_btn.setText, "allow_add_selected")
        self._t.bind(self.add_file_btn.setText, "rule_add_file")
        self._t.bind(self.remove_btn.setText, "remove")
        row.addWidget(self.add_sel_btn)
        row.addWidget(self.add_file_btn)
        row.addStretch(1)
        row.addWidget(self.remove_btn)
        layout.addLayout(row)
        self.toggle_btn.clicked.connect(lambda: self.toggle_requested.emit(not self._active))
        self.add_sel_btn.clicked.connect(self.add_selected)
        self.add_file_btn.clicked.connect(self.add_from_file)
        self.remove_btn.clicked.connect(self.remove_selected)
        self.model.set_paths(self._settings.kill_switch_allow)
        self.set_active(False, 0.0)

    def retranslate(self) -> None:
        self._t.apply()
        self.model.retranslate()
        self.set_active(self._active, self._since)

    def set_active(self, active: bool, since: float) -> None:
        self._active, self._since = active, since
        if active:
            when = dt.datetime.fromtimestamp(since).strftime("%H:%M") if since else ""
            self.status.setText(tr("killswitch_on_since", time=when))
            self.toggle_btn.setText(tr("killswitch_turn_off"))
            self.toggle_btn.setObjectName("SuccessButton")
        else:
            self.status.setText(tr("killswitch_off_status"))
            self.toggle_btn.setText(tr("killswitch_turn_on"))
            self.toggle_btn.setObjectName("DangerButton")
        self.status.setProperty("on", active)
        for w in (self.status, self.toggle_btn):
            w.style().unpolish(w)
            w.style().polish(w)

    def set_busy(self, busy: bool) -> None:
        self.toggle_btn.setEnabled(not busy)

    def _commit(self, paths: list[str]) -> None:
        seen, unique = set(), []
        for p in paths:
            key = normalize_exe(p)
            if key not in seen:
                seen.add(key)
                unique.append(p)
        self._settings.kill_switch_allow = unique
        self._save()
        self.model.set_paths(unique)
        self.allowlist_changed.emit(list(unique))

    def add_paths(self, paths: list[str]) -> None:
        self._commit(self._settings.kill_switch_allow + [p for p in paths if p])

    def add_selected(self) -> None:
        groups = [g for g in self._selection() if g.blockable]
        if not groups:
            QMessageBox.information(self, APP_NAME, tr("select_program_first"))
            return
        self.add_paths([g.exe for g in groups])

    def add_from_file(self) -> None:
        path = pick_exe(self)
        if path:
            self.add_paths([path])

    def remove_selected(self) -> None:
        rows = {i.row() for i in self.view.selectionModel().selectedRows()}
        self._commit([p for i, p in enumerate(self._settings.kill_switch_allow) if i not in rows])


class HistoryTab(QWidget):
    PERIODS = (("period_today", 1), ("period_week", 7), ("period_month", 30))
    FILTERS = (("filter_all", None), ("ev_block", "block"), ("ev_unblock", "unblock"), ("ev_expire", "expire"),
               ("ev_rule_on", "rule_on"), ("ev_rule_off", "rule_off"), ("ev_killswitch_on", "killswitch_on"),
               ("ev_killswitch_off", "killswitch_off"))

    def __init__(self, history: HistoryStore | None, parent=None) -> None:
        super().__init__(parent)
        self._history = history
        self._t = TextBinder()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        usage_box = QWidget()
        usage_layout = QVBoxLayout(usage_box)
        usage_layout.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        usage_title = QLabel(objectName="SectionTitle")
        self._t.bind(usage_title.setText, "usage_title")
        self.period = QComboBox()
        head.addWidget(usage_title, 1)
        head.addWidget(self.period)
        usage_layout.addLayout(head)
        self.usage_model = UsageModel(self)
        self.usage_view = make_table(self.usage_model)
        self.usage_view.setColumnWidth(0, 180)
        usage_layout.addWidget(self.usage_view, 1)
        note = QLabel(objectName="Hint")
        note.setWordWrap(True)
        self._t.bind(note.setText, "usage_note")
        usage_layout.addWidget(note)

        events_box = QWidget()
        events_layout = QVBoxLayout(events_box)
        events_layout.setContentsMargins(0, 0, 0, 0)
        head2 = QHBoxLayout()
        events_title = QLabel(objectName="SectionTitle")
        self._t.bind(events_title.setText, "events_title")
        self.filter = QComboBox()
        head2.addWidget(events_title, 1)
        head2.addWidget(self.filter)
        events_layout.addLayout(head2)
        self.events_model = EventsModel(self)
        self.events_view = make_table(self.events_model)
        for col, width in enumerate([170, 150, 160]):
            self.events_view.setColumnWidth(col, width)
        events_layout.addWidget(self.events_view, 1)

        splitter.addWidget(usage_box)
        splitter.addWidget(events_box)
        splitter.setSizes([480, 620])
        layout.addWidget(splitter, 1)
        self._fill_combos()
        self.period.currentIndexChanged.connect(lambda _i: self.refresh())
        self.filter.currentIndexChanged.connect(lambda _i: self.refresh())
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._auto_refresh)
        self._timer.start(5000)

    def _fill_combos(self) -> None:
        for combo, items in ((self.period, self.PERIODS), (self.filter, self.FILTERS)):
            index = max(combo.currentIndex(), 0)
            combo.blockSignals(True)
            combo.clear()
            for key, value in items:
                combo.addItem(tr(key), value)
            combo.setCurrentIndex(index)
            combo.blockSignals(False)

    def retranslate(self) -> None:
        self._t.apply()
        self._fill_combos()
        self.usage_model.retranslate()
        self.events_model.retranslate()

    def _auto_refresh(self) -> None:
        if self.isVisible():
            self.refresh()

    def refresh(self) -> None:
        if self._history is None:
            return
        self.usage_model.set_rows(self._history.top_usage(days=self.period.currentData() or 1))
        self.events_model.set_events(self._history.recent_events(kind=self.filter.currentData()))


class SettingsTab(QWidget):
    changed = Signal(str)  # name of the setting that changed

    def __init__(self, settings: Settings, data_dir: str, autostart_supported: bool, parent=None) -> None:
        super().__init__(parent)
        self._settings = settings
        self._data_dir = data_dir
        self._t = TextBinder()
        wrapper = QVBoxLayout(self)
        wrapper.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea, QScrollArea > QWidget > QWidget { background: transparent; }")
        body = QWidget()
        scroll.setWidget(body)
        wrapper.addWidget(scroll)
        outer = QVBoxLayout(body)
        outer.setContentsMargins(12, 12, 12, 12)
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.FieldsStayAtSizeHint)
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(10)

        self.theme = QComboBox()
        self.tray = QCheckBox()
        self.close_to_tray = QCheckBox()
        self.notifications = QCheckBox()
        self.autostart = QCheckBox()
        self.autostart.setEnabled(autostart_supported)
        self.hostnames = QCheckBox()
        self.countries = QCheckBox()
        self.history_days = QSpinBox()
        self.history_days.setRange(1, 365)
        self.open_folder = QPushButton()

        labels = {}
        for key, widget in (("set_theme", self.theme), ("set_tray", self.tray),
                            ("set_close_to_tray", self.close_to_tray), ("set_notifications", self.notifications),
                            ("set_autostart", self.autostart), ("set_hostnames", self.hostnames),
                            ("set_countries", self.countries), ("set_history_days", self.history_days),
                            ("set_data_folder", self.open_folder)):
            label = QLabel()
            labels[key] = label
            self._t.bind(label.setText, key)
            form.addRow(label, widget)
        self._t.bind(self.tray.setText, "enabled")
        self._t.bind(self.close_to_tray.setText, "set_close_to_tray_desc")
        self._t.bind(self.notifications.setText, "set_notifications_desc")
        self._t.bind(self.autostart.setText, "set_autostart_desc")
        self._t.bind(self.hostnames.setText, "set_hostnames_desc")
        self._t.bind(self.countries.setText, "set_countries_desc")
        self._t.bind(self.history_days.setSuffix, "days_suffix")
        self._t.bind(self.open_folder.setText, "open")
        outer.addLayout(form)
        privacy = QLabel(objectName="Hint")
        privacy.setWordWrap(True)
        self._t.bind(privacy.setText, "privacy_note")
        outer.addWidget(privacy)
        outer.addStretch(1)

        self.load_values(autostart_enabled=False)
        self.theme.currentIndexChanged.connect(lambda _i: self._set("theme", self.theme.currentData()))
        self.tray.toggled.connect(lambda v: self._set("tray_enabled", v))
        self.close_to_tray.toggled.connect(lambda v: self._set("close_to_tray", v))
        self.notifications.toggled.connect(lambda v: self._set("notifications", v))
        self.autostart.toggled.connect(lambda _v: self.changed.emit("autostart"))
        self.hostnames.toggled.connect(lambda v: self._set("resolve_hostnames", v))
        self.countries.toggled.connect(lambda v: self._set("show_countries", v))
        self.history_days.valueChanged.connect(lambda v: self._set("history_days", v))
        self.open_folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(self._data_dir)))

    def _fill_theme(self) -> None:
        self.theme.blockSignals(True)
        self.theme.clear()
        self.theme.addItem(tr("theme_dark"), "dark")
        self.theme.addItem(tr("theme_light"), "light")
        self.theme.setCurrentIndex(0 if self._settings.theme == "dark" else 1)
        self.theme.blockSignals(False)

    def load_values(self, autostart_enabled: bool) -> None:
        s = self._settings
        self._fill_theme()
        for widget, value in ((self.tray, s.tray_enabled), (self.close_to_tray, s.close_to_tray),
                              (self.notifications, s.notifications), (self.autostart, autostart_enabled),
                              (self.hostnames, s.resolve_hostnames), (self.countries, s.show_countries)):
            widget.blockSignals(True)
            widget.setChecked(value)
            widget.blockSignals(False)
        self.history_days.blockSignals(True)
        self.history_days.setValue(s.history_days)
        self.history_days.blockSignals(False)
        self.close_to_tray.setEnabled(s.tray_enabled)

    def set_autostart_checked(self, value: bool) -> None:
        self.autostart.blockSignals(True)
        self.autostart.setChecked(value)
        self.autostart.blockSignals(False)

    def _set(self, name: str, value) -> None:
        setattr(self._settings, name, value)
        self.close_to_tray.setEnabled(self._settings.tray_enabled)
        self.changed.emit(name)

    def retranslate(self) -> None:
        self._t.apply()
        self._fill_theme()
