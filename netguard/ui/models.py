"""Qt table models."""
from __future__ import annotations

import datetime as dt
import os

from PySide6.QtCore import QAbstractTableModel, QFileInfo, QLocale, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtWidgets import QFileIconProvider

from ..blocker import BlockEntry
from ..firewall import make_rule_id
from ..history import Event, UsageRow
from ..i18n import WEEK_ORDER, day_name, join, ltr, tr
from ..monitor import Connection, ProcessGroup
from ..policies import Policy, format_hhmm
from . import theme

SORT_ROLE = Qt.ItemDataRole.UserRole + 1
DisplayRole = Qt.ItemDataRole.DisplayRole
CENTER = int(Qt.AlignmentFlag.AlignCenter)


def format_rate(bps: float) -> str:
    return format_bytes(bps) + "/s"


def format_bytes(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return ""


def format_remaining(seconds: float | None) -> str:
    if seconds is None:
        return tr("until_manual")
    seconds = int(round(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes:02d}:{secs:02d}"


def country_name(code: str) -> str:
    try:
        territory = QLocale.codeToTerritory(code)
        if territory != QLocale.Territory.AnyTerritory:
            return QLocale.territoryToString(territory)
    except (AttributeError, TypeError):
        pass
    return code


class IconCache:
    def __init__(self) -> None:
        self._provider = QFileIconProvider()
        self._cache: dict[str, object] = {}
        self._default = None

    def icon(self, exe: str):
        if exe in self._cache:
            return self._cache[exe]
        if exe and os.path.exists(exe):
            icon = self._provider.icon(QFileInfo(exe))
        else:
            if self._default is None:
                self._default = self._provider.icon(QFileIconProvider.IconType.File)
            icon = self._default
        self._cache[exe] = icon
        return icon


class _BaseModel(QAbstractTableModel):
    HEADER_KEYS: list[str] = []

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADER_KEYS)

    def headerData(self, section, orientation, role=DisplayRole):
        if role == DisplayRole and orientation == Qt.Orientation.Horizontal:
            return tr(self.HEADER_KEYS[section])
        return None

    def retranslate(self) -> None:
        if self.HEADER_KEYS:
            self.headerDataChanged.emit(Qt.Orientation.Horizontal, 0, len(self.HEADER_KEYS) - 1)
        rows = self.rowCount()
        if rows:
            self.dataChanged.emit(self.index(0, 0), self.index(rows - 1, len(self.HEADER_KEYS) - 1))


class ProcessTableModel(_BaseModel):
    HEADER_KEYS = ["col_status", "col_program", "col_down", "col_up", "col_destinations", "col_external",
                   "col_tcp", "col_listen", "col_udp", "col_pid", "col_remote_ips", "col_path"]
    (COL_STATUS, COL_NAME, COL_DOWN, COL_UP, COL_DEST, COL_EXT, COL_TCP, COL_LISTEN, COL_UDP,
     COL_PID, COL_REMOTE, COL_PATH) = range(12)
    ADVANCED_COLUMNS = (COL_DOWN, COL_UP, COL_DEST)
    NUMERIC = (COL_EXT, COL_TCP, COL_LISTEN, COL_UDP)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._groups: list[ProcessGroup] = []
        self._rule_ids: list[str | None] = []
        self._blocked: frozenset[str] = frozenset()
        self._icons = IconCache()

    def set_groups(self, groups: list[ProcessGroup], blocked_ids: frozenset[str]) -> None:
        self.beginResetModel()
        self._groups = list(groups)
        self._rule_ids = [make_rule_id(g.exe) if g.exe else None for g in self._groups]
        self._blocked = frozenset(blocked_ids)
        self.endResetModel()

    def set_blocked(self, blocked_ids: frozenset[str]) -> None:
        blocked_ids = frozenset(blocked_ids)
        if blocked_ids == self._blocked:
            return
        self._blocked = blocked_ids
        self.retranslate()

    def group_at(self, row: int) -> ProcessGroup:
        return self._groups[row]

    def is_blocked_row(self, row: int) -> bool:
        rid = self._rule_ids[row]
        return rid is not None and rid in self._blocked

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._groups)

    def _status(self, row: int, group: ProcessGroup) -> tuple[str, int]:
        if self.is_blocked_row(row):
            return tr("status_blocked"), 0
        if group.external_count:
            return tr("status_online"), 1
        return tr("status_idle"), 2

    @staticmethod
    def _destinations_text(group: ProcessGroup) -> str:
        parts = []
        for ip, host, country in group.destinations()[:3]:
            label = host or ip
            parts.append(f"{label} ({country})" if country else label)
        extra = len(group.remote_ips) - 3
        return join(parts) + (f"  (+{extra})" if extra > 0 else "")

    def data(self, index: QModelIndex, role=DisplayRole):
        if not index.isValid():
            return None
        row, col = index.row(), index.column()
        g = self._groups[row]
        blocked = self.is_blocked_row(row)

        if role in (DisplayRole, SORT_ROLE):
            sort = role == SORT_ROLE
            if col == self.COL_STATUS:
                text, rank = self._status(row, g)
                return rank if sort else text
            if col == self.COL_NAME:
                return g.name.lower() if sort else g.name
            if col == self.COL_PID:
                pids = sorted(g.pids)
                if sort:
                    return pids[0] if pids else 0
                text = ", ".join(map(str, pids[:4]))
                return ltr(text + (f" (+{len(pids) - 4})" if len(pids) > 4 else ""))
            if col == self.COL_DOWN:
                return g.rate_down if sort else (ltr(format_rate(g.rate_down)) if g.rate_down else "—")
            if col == self.COL_UP:
                return g.rate_up if sort else (ltr(format_rate(g.rate_up)) if g.rate_up else "—")
            if col == self.COL_EXT:
                return g.external_count
            if col == self.COL_TCP:
                return g.active_tcp_count
            if col == self.COL_LISTEN:
                return g.listen_count
            if col == self.COL_UDP:
                return g.udp_count
            if col == self.COL_DEST:
                return len(g.remote_ips) if sort else ltr(self._destinations_text(g))
            if col == self.COL_REMOTE:
                ips = g.remote_ips
                if sort:
                    return len(ips)
                return ltr(join(ips[:3]) + (f"  (+{len(ips) - 3})" if len(ips) > 3 else ""))
            if col == self.COL_PATH:
                if sort:
                    return g.exe.lower()
                return ltr(g.exe) if g.exe else tr("path_unavailable")

        if role == Qt.ItemDataRole.ForegroundRole:
            if col == self.COL_STATUS:
                return theme.color("danger" if blocked else ("success" if g.external_count else "muted"))
            if col == self.COL_PATH:
                return theme.color("muted")
            if col in self.NUMERIC and not self.data(index, SORT_ROLE):
                return theme.color("muted")
            if col in (self.COL_DOWN, self.COL_UP):
                rate = g.rate_down if col == self.COL_DOWN else g.rate_up
                return theme.color("accent" if rate > 0 else "muted")
        if role == Qt.ItemDataRole.BackgroundRole and blocked:
            return theme.color("blocked_row")
        if role == Qt.ItemDataRole.DecorationRole and col == self.COL_NAME:
            return self._icons.icon(g.exe)
        if role == Qt.ItemDataRole.TextAlignmentRole and col in (self.COL_STATUS, self.COL_DOWN, self.COL_UP,
                                                                  *self.NUMERIC):
            return CENTER
        if role == Qt.ItemDataRole.ToolTipRole:
            if col == self.COL_REMOTE and g.remote_ips:
                return "\n".join(g.remote_ips)
            if col == self.COL_DEST and g.remote_ips:
                lines = []
                for ip, host, country in g.destinations():
                    extra = f"  —  {country_name(country)}" if country else ""
                    lines.append(f"{host or '?'}  [{ip}]{extra}")
                return "\n".join(lines)
            if col in (self.COL_NAME, self.COL_PATH):
                tip = g.exe or tr("tip_no_path")
                if g.is_store_app:
                    tip += "\n" + tr("tip_store_app")
                return f"{g.name}\n{tip}"
            if col == self.COL_PID:
                return ", ".join(map(str, sorted(g.pids)))
        return None


class ProcessFilterProxy(QSortFilterProxyModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._text = ""
        self._only_internet = True
        self.setSortRole(SORT_ROLE)
        self.setDynamicSortFilter(True)

    def _apply(self, change) -> None:
        # Qt >= 6.10 deprecates invalidateFilter() in favour of begin/endFilterChange().
        if hasattr(self, "beginFilterChange"):
            self.beginFilterChange()
            change()
            self.endFilterChange()
        else:
            change()
            self.invalidateFilter()

    def set_text(self, text: str) -> None:
        self._apply(lambda: setattr(self, "_text", text.strip().lower()))

    def set_only_internet(self, enabled: bool) -> None:
        self._apply(lambda: setattr(self, "_only_internet", enabled))

    def refilter(self) -> None:
        self._apply(lambda: None)

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model: ProcessTableModel = self.sourceModel()  # type: ignore[assignment]
        group = model.group_at(source_row)
        blocked = model.is_blocked_row(source_row)
        if self._only_internet and not blocked and not group.external_count:
            return False
        return not self._text or self._text in group.search_blob


class BlockedTableModel(_BaseModel):
    HEADER_KEYS = ["col_program", "col_path", "col_reason", "col_since", "col_remaining"]
    COL_REMAINING = 4

    def __init__(self, parent=None, policy_names=None) -> None:
        super().__init__(parent)
        self._entries: list[BlockEntry] = []
        self._now = 0.0
        self._policy_names = policy_names or (lambda ids: [])

    def update_entries(self, entries: list[BlockEntry], now: float) -> None:
        same_rows = [e.rule_id for e in entries] == [e.rule_id for e in self._entries]
        if same_rows:  # keep selection & scroll; just repaint
            self._entries, self._now = entries, now
            if entries:
                self.dataChanged.emit(self.index(0, 0), self.index(len(entries) - 1, len(self.HEADER_KEYS) - 1))
            return
        self.beginResetModel()
        self._entries, self._now = entries, now
        self.endResetModel()

    def entry_at(self, row: int) -> BlockEntry:
        return self._entries[row]

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._entries)

    def _reason(self, e: BlockEntry) -> str:
        parts = []
        if e.manual:
            parts.append(tr("reason_manual"))
        if e.policies:
            names = self._policy_names(e.policies) or [tr("reason_rule_generic")]
            parts.append(tr("reason_rule", names=join(names)))
        return " + ".join(parts)

    def data(self, index: QModelIndex, role=DisplayRole):
        if not index.isValid():
            return None
        e = self._entries[index.row()]
        col = index.column()
        if role == DisplayRole:
            if col == 0:
                return e.name
            if col == 1:
                return ltr(e.exe)
            if col == 2:
                return self._reason(e)
            if col == 3:
                return dt.datetime.fromtimestamp(e.created_at).strftime("%H:%M:%S")
            if col == 4:
                if not e.manual:
                    return tr("while_rule_active")
                return format_remaining(e.remaining(self._now))
        if role == Qt.ItemDataRole.ForegroundRole:
            if col == 1:
                return theme.color("muted")
            if col == 4:
                return theme.color("danger")
        if role == Qt.ItemDataRole.TextAlignmentRole and col in (3, 4):
            return CENTER
        if role == Qt.ItemDataRole.ToolTipRole and col == 1:
            return e.exe
        return None


class ConnectionsModel(_BaseModel):
    HEADER_KEYS = ["col_protocol", "col_version", "col_pid", "col_local", "col_remote", "col_host",
                   "col_country", "col_state"]
    COL_HOST, COL_COUNTRY = 5, 6

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[Connection] = []
        self._info: dict[str, tuple[str, str]] = {}

    def set_connections(self, connections: list[Connection], info: dict[str, tuple[str, str]] | None = None) -> None:
        self.beginResetModel()
        self._rows = sorted(connections, key=lambda c: (not c.is_external, c.protocol, c.remote_ip, c.local_port))
        self._info = info or {}
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def data(self, index: QModelIndex, role=DisplayRole):
        if not index.isValid():
            return None
        c = self._rows[index.row()]
        col = index.column()
        host, country = self._info.get(c.remote_ip, ("", ""))
        if role == DisplayRole:
            return [c.protocol, c.family, c.pid, ltr(c.local), ltr(c.remote) or "—", ltr(host) or "—",
                    country or "—", c.status or "—"][col]
        if role == Qt.ItemDataRole.ToolTipRole and col == self.COL_COUNTRY and country:
            return country_name(country)
        if role == Qt.ItemDataRole.ForegroundRole and not c.is_external:
            return theme.color("muted")
        if role == Qt.ItemDataRole.TextAlignmentRole and col in (0, 1, 2, 6, 7):
            return CENTER
        return None


class PoliciesModel(_BaseModel):
    HEADER_KEYS = ["col_program", "col_type", "col_days", "col_time", "col_enabled", "col_now"]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._items: list[Policy] = []

    def set_policies(self, items: list[Policy]) -> None:
        self.beginResetModel()
        self._items = list(items)
        self.endResetModel()

    def policy_at(self, row: int) -> Policy:
        return self._items[row]

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._items)

    @staticmethod
    def days_text(p: Policy) -> str:
        if p.kind == "always" or len(p.days) == 7:
            return tr("every_day")
        return join(day_name(d) for d in WEEK_ORDER if d in p.days)

    def data(self, index: QModelIndex, role=DisplayRole):
        if not index.isValid():
            return None
        p = self._items[index.row()]
        col = index.column()
        active = p.is_active(dt.datetime.now())
        if role == DisplayRole:
            if col == 0:
                return p.name
            if col == 1:
                return tr("kind_always") if p.kind == "always" else tr("kind_schedule")
            if col == 2:
                return self.days_text(p)
            if col == 3:
                if p.kind == "always" or p.start == p.end:
                    return tr("all_day")
                return ltr(f"{format_hhmm(p.start)} → {format_hhmm(p.end)}")
            if col == 4:
                return tr("yes") if p.enabled else tr("no")
            if col == 5:
                return tr("rule_active_now") if active else tr("rule_inactive_now")
        if role == Qt.ItemDataRole.ForegroundRole:
            if col == 5:
                return theme.color("danger" if active else "muted")
            if col == 4 and not p.enabled:
                return theme.color("muted")
        if role == Qt.ItemDataRole.TextAlignmentRole and col in (1, 3, 4, 5):
            return CENTER
        if role == Qt.ItemDataRole.ToolTipRole and col == 0:
            return p.exe
        return None


class AllowListModel(_BaseModel):
    HEADER_KEYS = ["col_program", "col_path"]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._paths: list[str] = []

    def set_paths(self, paths: list[str]) -> None:
        self.beginResetModel()
        self._paths = list(paths)
        self.endResetModel()

    def path_at(self, row: int) -> str:
        return self._paths[row]

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._paths)

    def data(self, index: QModelIndex, role=DisplayRole):
        if not index.isValid():
            return None
        path = self._paths[index.row()]
        if role == DisplayRole:
            return os.path.basename(path.replace("\\", "/")) if index.column() == 0 else ltr(path)
        if role == Qt.ItemDataRole.ForegroundRole and index.column() == 1:
            return theme.color("muted")
        return None


EVENT_KEYS = {
    "block": "ev_block", "unblock": "ev_unblock", "expire": "ev_expire", "rule_on": "ev_rule_on",
    "rule_off": "ev_rule_off", "killswitch_on": "ev_killswitch_on", "killswitch_off": "ev_killswitch_off",
}


class EventsModel(_BaseModel):
    HEADER_KEYS = ["col_time", "col_event", "col_program", "col_details"]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[Event] = []

    def set_events(self, rows: list[Event]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def data(self, index: QModelIndex, role=DisplayRole):
        if not index.isValid():
            return None
        e = self._rows[index.row()]
        col = index.column()
        if role == DisplayRole:
            if col == 0:
                return ltr(dt.datetime.fromtimestamp(e.ts).strftime("%Y-%m-%d  %H:%M:%S"))
            if col == 1:
                return tr(EVENT_KEYS.get(e.kind, "ev_block"))
            if col == 2:
                return e.name or "—"
            if col == 3:
                return ltr(e.detail or e.exe)
        if role == Qt.ItemDataRole.ForegroundRole:
            if col == 1:
                bad = e.kind in ("block", "rule_on", "killswitch_on")
                return theme.color("danger" if bad else "success")
            if col == 3:
                return theme.color("muted")
        return None


class UsageModel(_BaseModel):
    HEADER_KEYS = ["col_program", "col_download", "col_upload", "col_total"]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[UsageRow] = []

    def set_rows(self, rows: list[UsageRow]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def data(self, index: QModelIndex, role=DisplayRole):
        if not index.isValid():
            return None
        r = self._rows[index.row()]
        col = index.column()
        if role == DisplayRole:
            return [r.name, ltr(format_bytes(r.bytes_in)), ltr(format_bytes(r.bytes_out)),
                    ltr(format_bytes(r.total))][col]
        if role == Qt.ItemDataRole.TextAlignmentRole and col > 0:
            return CENTER
        if role == Qt.ItemDataRole.ToolTipRole and col == 0:
            return r.exe
        return None
