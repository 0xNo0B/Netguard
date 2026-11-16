"""Tear down a process's existing TCP connections (Windows, IPv4).

Firewall rules stop *new* connections; long-lived ones (downloads, streams,
game sessions) may keep flowing until reset. SetTcpEntry with
MIB_TCP_STATE_DELETE_TCB resets them immediately. Requires administrator.
Windows exposes no equivalent for IPv6 sockets, so those are skipped.
"""
from __future__ import annotations

import ctypes
import logging
import socket
from typing import Callable, Iterable

import psutil

from .config import IS_WINDOWS
from .monitor import ACTIVE_TCP_STATES, is_local_ip

log = logging.getLogger(__name__)

MIB_TCP_STATE_DELETE_TCB = 12


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.c_uint32),
        ("dwLocalAddr", ctypes.c_uint32),
        ("dwLocalPort", ctypes.c_uint32),
        ("dwRemoteAddr", ctypes.c_uint32),
        ("dwRemotePort", ctypes.c_uint32),
    ]


def _ip_to_dword(ip: str) -> int:
    # The DWORD holds the address in network byte order: its in-memory bytes
    # (little-endian x86/ARM) must equal the 4 address octets.
    return int.from_bytes(socket.inet_aton(ip), "little")


def _port_to_dword(port: int) -> int:
    return socket.htons(port)


def build_row(local_ip: str, local_port: int, remote_ip: str, remote_port: int) -> MIB_TCPROW:
    return MIB_TCPROW(
        MIB_TCP_STATE_DELETE_TCB,
        _ip_to_dword(local_ip),
        _port_to_dword(local_port),
        _ip_to_dword(remote_ip),
        _port_to_dword(remote_port),
    )


def _windows_set_tcp_entry() -> Callable:
    func = ctypes.windll.iphlpapi.SetTcpEntry  # type: ignore[attr-defined]
    func.argtypes = [ctypes.POINTER(MIB_TCPROW)]
    func.restype = ctypes.c_uint32
    return func


def close_tcp_connections(
    pids: Iterable[int],
    conn_provider: Callable[[], Iterable] | None = None,
    set_tcp_entry: Callable | None = None,
) -> tuple[int, int]:
    """Reset external IPv4 TCP connections of `pids`. Returns (closed, failed)."""
    if set_tcp_entry is None:
        if not IS_WINDOWS:
            return 0, 0
        set_tcp_entry = _windows_set_tcp_entry()
    provider = conn_provider or (lambda: psutil.net_connections(kind="tcp4"))
    wanted = set(pids)
    closed = failed = 0
    for conn in provider():
        if conn.pid not in wanted or not conn.raddr or conn.status not in ACTIVE_TCP_STATES:
            continue
        if is_local_ip(conn.raddr.ip):  # keep local IPC alive
            continue
        try:
            row = build_row(conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port)
        except OSError:  # not an IPv4 address
            continue
        rc = set_tcp_entry(ctypes.byref(row))
        if rc == 0:
            closed += 1
        else:
            failed += 1
            log.debug("SetTcpEntry failed (%s) for %s -> %s", rc, conn.laddr, conn.raddr)
    return closed, failed
