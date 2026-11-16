"""System tray icon with menu and notifications (advanced mode)."""
from __future__ import annotations

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from ..i18n import tr
from .icons import app_icon


class TrayController(QObject):
    show_requested = Signal()
    killswitch_toggled = Signal(bool)
    unblock_all_requested = Signal()
    quit_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.available = QSystemTrayIcon.isSystemTrayAvailable()
        self._icon_normal = app_icon(False)
        self._icon_alert = app_icon(True)
        self._tray = QSystemTrayIcon(self._icon_normal, parent)
        self._menu = QMenu()
        self._act_show = self._menu.addAction("")
        self._act_show.triggered.connect(self.show_requested.emit)
        self._menu.addSeparator()
        self._act_kill = self._menu.addAction("")
        self._act_kill.setCheckable(True)
        self._act_kill.toggled.connect(self._on_kill_toggled)
        self._act_unblock = self._menu.addAction("")
        self._act_unblock.triggered.connect(self.unblock_all_requested.emit)
        self._menu.addSeparator()
        self._act_quit = self._menu.addAction("")
        self._act_quit.triggered.connect(self.quit_requested.emit)
        self._tray.setContextMenu(self._menu)
        self._tray.activated.connect(self._on_activated)
        self._updating = False
        self.retranslate()

    def _on_activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self.show_requested.emit()

    def _on_kill_toggled(self, checked: bool) -> None:
        if not self._updating:
            self.killswitch_toggled.emit(checked)

    def retranslate(self) -> None:
        self._act_show.setText(tr("tray_show"))
        self._act_kill.setText(tr("killswitch"))
        self._act_unblock.setText(tr("unblock_all"))
        self._act_quit.setText(tr("tray_quit"))
        self._tray.setToolTip("NetGuard")

    def set_visible(self, visible: bool) -> None:
        self._tray.setVisible(visible and self.available)

    @property
    def visible(self) -> bool:
        return self.available and self._tray.isVisible()

    def set_killswitch(self, active: bool) -> None:
        self._updating = True
        self._act_kill.setChecked(active)
        self._updating = False
        self._tray.setIcon(self._icon_alert if active else self._icon_normal)

    def notify(self, title: str, message: str) -> None:
        if self.visible:
            self._tray.showMessage(title, message, self._icon_normal, 5000)
