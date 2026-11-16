"""Application-wide constants and small path helpers."""
from __future__ import annotations

import ntpath
import os
import sys
from pathlib import Path

APP_NAME = "NetGuard"
APP_VERSION = "1.0.0"

# Every firewall rule this app creates starts with this prefix, so leftovers
# from a crash can be found and removed safely without touching other rules.
RULE_PREFIX = "NetGuard-"

IS_WINDOWS = sys.platform == "win32"

STATE_FILE_NAME = "state.json"
LOG_FILE_NAME = "netguard.log"
LOCK_FILE_NAME = "netguard.lock"

DEFAULT_SCAN_INTERVAL_MS = 2000

# Blocking these cuts networking for large parts of Windows (DNS, updates,
# time sync, domain logon...). The UI asks for explicit confirmation.
CRITICAL_PROCESSES = frozenset(
    {
        "system",
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "wininit.exe",
        "winlogon.exe",
        "csrss.exe",
        "smss.exe",
        "spoolsv.exe",
    }
)


def normalize_exe(path: str) -> str:
    """Canonical form of an executable path. Windows paths (drive letter or UNC)
    are case-insensitive whatever OS the code runs on, so rule ids match."""
    if IS_WINDOWS or (len(path) > 2 and path[1] == ":") or path.startswith("\\\\"):
        return ntpath.normcase(ntpath.normpath(path))
    return os.path.normpath(path)


def app_data_dir() -> Path:
    """Per-user writable directory for state and logs."""
    if IS_WINDOWS:
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    path = Path(base) / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path

SETTINGS_FILE_NAME = "settings.json"
POLICIES_FILE_NAME = "policies.json"
KILLSWITCH_FILE_NAME = "killswitch.json"
HISTORY_FILE_NAME = "history.sqlite3"
COUNTRY_CACHE_FILE_NAME = "countries.json"
POLICY_SYNC_INTERVAL_S = 5
