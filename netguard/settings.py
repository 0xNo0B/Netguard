"""User settings persisted as JSON in the app data directory."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

log = logging.getLogger(__name__)

MODES = ("normal", "advanced")
LANGUAGES = ("ar", "en")
THEMES = ("dark", "light")


@dataclass
class Settings:
    mode: str = "normal"
    language: str = "ar"
    theme: str = "dark"
    scan_interval_s: int = 2
    # Advanced mode only
    tray_enabled: bool = True
    close_to_tray: bool = True
    notifications: bool = True
    resolve_hostnames: bool = True
    show_countries: bool = False  # sends public IPs to api.country.is -> opt-in
    history_days: int = 30
    kill_switch_allow: list[str] = field(default_factory=list)

    @property
    def advanced(self) -> bool:
        return self.mode == "advanced"

    def normalized(self) -> "Settings":
        if self.mode not in MODES:
            self.mode = "normal"
        if self.language not in LANGUAGES:
            self.language = "ar"
        if self.theme not in THEMES:
            self.theme = "dark"
        self.scan_interval_s = min(30, max(1, int(self.scan_interval_s)))
        self.history_days = min(365, max(1, int(self.history_days)))
        self.kill_switch_allow = [str(p) for p in self.kill_switch_allow if p]
        return self

    @classmethod
    def load(cls, path: Path) -> "Settings":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        except (OSError, ValueError) as exc:
            log.error("Bad settings file %s: %s", path, exc)
            return cls()
        known = {f.name for f in fields(cls)}
        try:
            return cls(**{k: v for k, v in data.items() if k in known}).normalized()
        except (TypeError, ValueError) as exc:
            log.error("Invalid settings values: %s", exc)
            return cls()

    def save(self, path: Path) -> None:
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, path)
        except OSError as exc:
            log.error("Could not save settings: %s", exc)
