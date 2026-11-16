"""Per-application TCP throughput using Windows TCP Extended Statistics.

For every live TCP connection we enable EStats "Data" collection once
(SetPerTcp[6]ConnectionEStats, needs admin) and then read the cumulative
DataBytesIn / DataBytesOut counters (GetPerTcp[6]ConnectionEStats) on every
scan. Rate = counter delta / elapsed time, summed per program.
UDP has no per-socket counters on Windows, so UDP traffic (e.g. some games,
QUIC) is not included.
"""
from __future__ import annotations

import ctypes
import logging
import socket
import time
from typing import Callable, Iterable, Protocol

import psutil

from .config import IS_WINDOWS
from .monitor import Connection, ProcessGroup

log = logging.getLogger(__name__)

TCP_CONNECTION_ESTATS_DATA = 1
NO_ERROR = 0

_MIB_STATE = {
    psutil.CONN_SYN_SENT: 3,
    psutil.CONN_SYN_RECV: 4,
    psutil.CONN_ESTABLISHED: 5,
    psutil.CONN_FIN_WAIT1: 6,
    psutil.CONN_FIN_WAIT2: 7,
    psutil.CONN_CLOSE_WAIT: 8,
    psutil.CONN_CLOSING: 9,
    psutil.CONN_LAST_ACK: 10,
}


class TCP_ESTATS_DATA_RW_v0(ctypes.Structure):
    _fields_ = [("EnableCollection", ctypes.c_ubyte)]


class TCP_ESTATS_DATA_ROD_v0(ctypes.Structure):
    # Field order/types from tcpestats.h (natural alignment, same as MSVC).
    _fields_ = [
        ("DataBytesOut", ctypes.c_uint64),
        ("DataSegsOut", ctypes.c_uint64),
        ("DataBytesIn", ctypes.c_uint64),
        ("DataSegsIn", ctypes.c_uint64),
        ("SegsOut", ctypes.c_uint64),
        ("SegsIn", ctypes.c_uint64),
        ("SoftErrors", ctypes.c_uint32),
        ("SoftErrorReason", ctypes.c_uint32),
        ("SndUna", ctypes.c_uint32),
        ("SndNxt", ctypes.c_uint32),
        ("SndMax", ctypes.c_uint32),
        ("ThruBytesAcked", ctypes.c_uint64),
        ("RcvNxt", ctypes.c_uint32),
        ("ThruBytesReceived", ctypes.c_uint64),
    ]


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.c_uint32),
        ("dwLocalAddr", ctypes.c_uint32),
        ("dwLocalPort", ctypes.c_uint32),
        ("dwRemoteAddr", ctypes.c_uint32),
        ("dwRemotePort", ctypes.c_uint32),
    ]


class MIB_TCP6ROW(ctypes.Structure):
    _fields_ = [
        ("State", ctypes.c_uint32),
        ("LocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", ctypes.c_uint32),
        ("dwLocalPort", ctypes.c_uint32),
        ("RemoteAddr", ctypes.c_ubyte * 16),
        ("dwRemoteScopeId", ctypes.c_uint32),
        ("dwRemotePort", ctypes.c_uint32),
    ]


def make_row(conn: Connection):
    """MIB_TCPROW / MIB_TCP6ROW for a connection (addresses in network order)."""
    state = _MIB_STATE.get(conn.status, 5)
    if conn.family == "IPv4":
        return MIB_TCPROW(
            state,
            int.from_bytes(socket.inet_aton(conn.local_ip), "little"),
            socket.htons(conn.local_port),
            int.from_bytes(socket.inet_aton(conn.remote_ip), "little"),
            socket.htons(conn.remote_port),
        )
    row = MIB_TCP6ROW()
    row.State = state
    row.LocalAddr[:] = socket.inet_pton(socket.AF_INET6, conn.local_ip.split("%")[0])
    row.dwLocalPort = socket.htons(conn.local_port)
    row.RemoteAddr[:] = socket.inet_pton(socket.AF_INET6, conn.remote_ip.split("%")[0])
    row.dwRemotePort = socket.htons(conn.remote_port)
    return row


class EStatsApi(Protocol):
    def enable(self, conn: Connection) -> bool: ...
    def read(self, conn: Connection) -> tuple[int, int] | None: ...


class WindowsEStatsApi:
    def __init__(self) -> None:
        lib = ctypes.WinDLL("iphlpapi")  # type: ignore[attr-defined]
        self._set4, self._get4 = lib.SetPerTcpConnectionEStats, lib.GetPerTcpConnectionEStats
        self._set6, self._get6 = lib.SetPerTcp6ConnectionEStats, lib.GetPerTcp6ConnectionEStats
        for fn in (self._set4, self._get4, self._set6, self._get6):
            fn.restype = ctypes.c_ulong

    def enable(self, conn: Connection) -> bool:
        row = make_row(conn)
        rw = TCP_ESTATS_DATA_RW_v0(1)
        setter = self._set4 if conn.family == "IPv4" else self._set6
        rc = setter(ctypes.byref(row), TCP_CONNECTION_ESTATS_DATA, ctypes.byref(rw), 0,
                    ctypes.sizeof(rw), 0)
        return rc == NO_ERROR

    def read(self, conn: Connection) -> tuple[int, int] | None:
        row = make_row(conn)
        rod = TCP_ESTATS_DATA_ROD_v0()
        getter = self._get4 if conn.family == "IPv4" else self._get6
        rc = getter(ctypes.byref(row), TCP_CONNECTION_ESTATS_DATA, None, 0, 0, None, 0, 0,
                    ctypes.byref(rod), 0, ctypes.sizeof(rod))
        if rc != NO_ERROR:
            return None
        return int(rod.DataBytesIn), int(rod.DataBytesOut)


def create_api() -> EStatsApi | None:
    if not IS_WINDOWS:
        return None
    try:
        return WindowsEStatsApi()
    except (OSError, AttributeError) as exc:
        log.warning("TCP EStats unavailable: %s", exc)
        return None


class BandwidthTracker:
    def __init__(self, api: EStatsApi | None = None, clock: Callable[[], float] = time.monotonic) -> None:
        self._api = api
        self._clock = clock
        self._enabled: set[tuple] = set()
        self._last: dict[tuple, tuple[int, int]] = {}
        self._last_time: float | None = None

    @property
    def available(self) -> bool:
        return self._api is not None

    def reset(self) -> None:
        self._enabled.clear()
        self._last.clear()
        self._last_time = None

    def update(self, groups: Iterable[ProcessGroup]) -> None:
        if self._api is None:
            return
        now = self._clock()
        dt = None if self._last_time is None else max(now - self._last_time, 1e-3)
        self._last_time = now
        seen: set[tuple] = set()
        for group in groups:
            down = up = 0
            for conn in group.connections:
                if not conn.is_active_tcp or not conn.remote_ip:
                    continue
                key = conn.flow_key
                seen.add(key)
                try:
                    if key not in self._enabled:
                        if not self._api.enable(conn):
                            continue
                        self._enabled.add(key)
                    counters = self._api.read(conn)
                except (OSError, ValueError) as exc:  # bad address etc.
                    log.debug("EStats failed for %s: %s", key, exc)
                    continue
                if counters is None:
                    continue
                previous = self._last.get(key)
                self._last[key] = counters
                if previous is not None:
                    down += max(0, counters[0] - previous[0])
                    up += max(0, counters[1] - previous[1])
            group.bytes_down, group.bytes_up = down, up
            if dt:
                group.rate_down, group.rate_up = down / dt, up / dt
        for key in list(self._last):
            if key not in seen:
                self._last.pop(key, None)
        self._enabled &= seen
