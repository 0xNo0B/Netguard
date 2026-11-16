"""NetGuard entry point.

Run:  python main.py               (asks for administrator via UAC on Windows)
      python main.py --no-elevate  (read-only view, no blocking)
      python main.py --minimized   (start hidden in the tray; used by autostart)
"""
from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler

from netguard.config import (
    APP_NAME,
    COUNTRY_CACHE_FILE_NAME,
    HISTORY_FILE_NAME,
    IS_WINDOWS,
    KILLSWITCH_FILE_NAME,
    LOCK_FILE_NAME,
    LOG_FILE_NAME,
    POLICIES_FILE_NAME,
    SETTINGS_FILE_NAME,
    STATE_FILE_NAME,
    app_data_dir,
)
from netguard.platform_utils import is_admin, relaunch_as_admin


def setup_logging() -> None:
    handler = RotatingFileHandler(
        app_data_dir() / LOG_FILE_NAME, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handlers: list[logging.Handler] = [handler]
    if sys.stderr is not None:  # pythonw / windowed exe have no console
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.INFO, handlers=handlers)


def main() -> int:
    setup_logging()
    log = logging.getLogger(APP_NAME)
    admin = is_admin()

    if IS_WINDOWS and not admin and "--no-elevate" not in sys.argv:
        if relaunch_as_admin(["--no-elevate"]):  # flag prevents a loop if elevation is refused later
            return 0
        log.warning("Elevation declined; starting in read-only mode")

    # Qt imports after the elevation decision so the non-elevated copy exits fast.
    from PySide6.QtCore import QLockFile, Qt
    from PySide6.QtWidgets import QApplication, QMessageBox

    from netguard import i18n
    from netguard.bandwidth import BandwidthTracker, create_api
    from netguard.blocker import BlockManager
    from netguard.firewall import create_backend
    from netguard.history import HistoryStore
    from netguard.hostnames import HostResolver
    from netguard.killswitch import KillSwitch
    from netguard.monitor import NetworkMonitor, ThroughputMeter
    from netguard.policies import PolicyStore
    from netguard.settings import Settings
    from netguard.ui.icons import app_icon
    from netguard.ui.main_window import MainWindow, Services
    from netguard.ui.theme import apply_theme

    data = app_data_dir()
    settings_path = data / SETTINGS_FILE_NAME
    settings = Settings.load(settings_path)
    i18n.set_language(settings.language)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(app_icon())
    app.setQuitOnLastWindowClosed(False)  # the tray keeps us alive; quit is explicit
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft if i18n.is_rtl() else Qt.LayoutDirection.LeftToRight)
    apply_theme(app, settings.theme)

    lock = QLockFile(str(data / LOCK_FILE_NAME))
    if not lock.tryLock(200):
        QMessageBox.information(None, APP_NAME, i18n.tr("already_running"))
        return 1

    backend = create_backend()
    history = HistoryStore(data / HISTORY_FILE_NAME)
    history.prune(settings.history_days)
    services = Services(
        manager=BlockManager(backend, data / STATE_FILE_NAME),
        settings=settings,
        settings_path=settings_path,
        policies=PolicyStore(data / POLICIES_FILE_NAME),
        killswitch=KillSwitch(backend, data / KILLSWITCH_FILE_NAME),
        history=history,
        bandwidth=BandwidthTracker(create_api() if admin else None),
        resolver=HostResolver(cache_path=data / COUNTRY_CACHE_FILE_NAME),
        data_dir=str(data),
    )

    can_block = admin or backend.simulated
    warnings: list[str] = []
    if IS_WINDOWS and not admin:
        warnings.append("warn_not_admin")
    if backend.simulated:
        warnings.append("warn_simulation")

    window = MainWindow(NetworkMonitor(), ThroughputMeter(), services, can_block=can_block, warnings=warnings)
    start_hidden = "--minimized" in sys.argv and settings.advanced and settings.tray_enabled and window.tray.available
    if not start_hidden:
        window.show()
    code = app.exec()
    history.close()
    lock.unlock()
    return code


if __name__ == "__main__":
    sys.exit(main())
