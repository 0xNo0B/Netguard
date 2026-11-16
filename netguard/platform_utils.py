"""OS helpers: admin detection, UAC elevation, opening Explorer."""
from __future__ import annotations

import ctypes
import logging
import os
import subprocess
import sys

from .config import IS_WINDOWS

log = logging.getLogger(__name__)


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except OSError:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def relaunch_as_admin(extra_args: list[str] | None = None) -> bool:
    """Ask UAC to restart this program elevated. True if the elevated copy started."""
    if not IS_WINDOWS:
        return False
    if getattr(sys, "frozen", False):  # PyInstaller exe
        args = sys.argv[1:]
    else:
        args = [os.path.abspath(sys.argv[0]), *sys.argv[1:]]
    args += extra_args or []
    params = subprocess.list2cmdline(args)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)  # type: ignore[attr-defined]
    log.info("UAC relaunch returned %s", rc)
    return int(rc) > 32


def reveal_in_file_manager(path: str) -> None:
    if IS_WINDOWS:
        subprocess.Popen(f'explorer.exe /select,"{path}"')
    else:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices

        QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(path)))
