"""Tiny translation layer: tr("key", **fmt) for Arabic / English.

Widgets register their text with a TextBinder so a language switch can
re-apply every string live without rebuilding the window.
"""
from __future__ import annotations

import logging
from typing import Callable

from .strings import STRINGS

log = logging.getLogger(__name__)

_language = "ar"


def set_language(language: str) -> None:
    global _language
    _language = language if language in ("ar", "en") else "ar"


def language() -> str:
    return _language


def is_rtl() -> bool:
    return _language == "ar"


def tr(key: str, **fmt) -> str:
    pair = STRINGS.get(key)
    if pair is None:
        log.error("missing translation key %r", key)
        return key
    text = pair[0] if _language == "ar" else pair[1]
    if fmt:
        try:
            return text.format(**fmt)
        except (KeyError, IndexError, ValueError):
            log.error("bad format args for %r", key)
    return text


def ltr(text: str) -> str:
    """Keep Latin/number runs (IPs, sizes, paths) in left-to-right order inside
    Arabic right-to-left cells (LRE … PDF embedding)."""
    return f"\u202a{text}\u202c" if _language == "ar" and text else text


def join(items) -> str:
    return ("، " if _language == "ar" else ", ").join(str(i) for i in items)


# Sunday-first, as used in Saudi Arabia; values are Python weekday() numbers.
WEEK_ORDER = (6, 0, 1, 2, 3, 4, 5)
_DAY_KEYS = {0: "day_mon", 1: "day_tue", 2: "day_wed", 3: "day_thu", 4: "day_fri", 5: "day_sat", 6: "day_sun"}


def day_name(weekday: int) -> str:
    return tr(_DAY_KEYS[weekday])


class TextBinder:
    """Remembers (setter, key, fmt) so all texts can be re-applied."""

    def __init__(self) -> None:
        self._items: list[tuple[Callable[[str], None], str, dict]] = []

    def bind(self, setter: Callable[[str], None], key: str, **fmt) -> None:
        self._items.append((setter, key, fmt))
        setter(tr(key, **fmt))

    def apply(self) -> None:
        for setter, key, fmt in self._items:
            setter(tr(key, **fmt))
