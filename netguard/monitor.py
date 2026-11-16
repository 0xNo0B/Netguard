"""Snapshot of the system's network sockets, grouped per executable."""
from __future__ import annotations

import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

import psutil

from .config import normalize_exe
from .win_appcontainer import get_app_container_sid, is_store_app_path

log = logging.getLogger(__name__)

ACTIVE_TCP_STATES = frozenset(
    {
        psutil.CONN_ESTABLISHED,
        psutil.CONN_SYN_SENT,
        psutil.CONN_SYN_RECV,
        psutil.CONN_FIN_WAIT1,
        psutil.CONN_FIN_WAIT2,
        psutil.CONN_CLOSE_WAIT,
        psutil.CONN_LAST_ACK,
        psutil.CONN_CLOSING,
    }
)


def is_local_ip(ip: str) -> bool:
    """True for loopback / unspecified addresses (not real internet peers)."""
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_loopback or addr.is_unspecified


def format_endpoint(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


@dataclass(frozen=True)
class Connection:
    pid: int
    protocol: str  # "TCP" | "UDP"
    family: str  # "IPv4" | "IPv6"
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str

    @property
    def local(self) -> str:
        return format_endpoint(self.local_ip, self.local_port) if self.local_ip else ""

    @property
    def remote(self) -> str:
        return format_endpoint(self.remote_ip, self.remote_port) if self.remote_ip else ""

    @property
    def is_active_tcp(self) -> bool:
        return self.protocol == "TCP" and self.status in ACTIVE_TCP_STATES

    @property
    def is_listening(self) -> bool:
        return self.protocol == "TCP" and self.status == psutil.CONN_LISTEN

    @property
    def flow_key(self) -> tuple:
        return (self.pid, self.protocol, self.local_ip, self.local_port, self.remote_ip, self.remote_port)

    @property
    def is_external(self) -> bool:
        """A live flow to a non-loopback peer, i.e. real network/internet traffic."""
        if not self.remote_ip or is_local_ip(self.remote_ip):
            return False
        return self.protocol == "UDP" or self.status in ACTIVE_TCP_STATES


@dataclass
class ProcessGroup:
    """All sockets belonging to one executable (all of its PIDs together)."""

    key: str
    name: str
    exe: str  # "" when the path could not be read (protected process)
    pids: set[int] = field(default_factory=set)
    connections: list[Connection] = field(default_factory=list)
    package_sid: str = ""  # Microsoft Store (AppContainer) apps
    rate_down: float = 0.0  # bytes/s, filled by BandwidthTracker (advanced mode)
    rate_up: float = 0.0
    bytes_down: int = 0  # bytes since the previous scan
    bytes_up: int = 0
    remote_info: dict[str, tuple[str, str]] = field(default_factory=dict)  # ip -> (host, country)

    @property
    def blockable(self) -> bool:
        return bool(self.exe)

    @property
    def is_store_app(self) -> bool:
        return bool(self.package_sid)

    def destinations(self) -> list[tuple[str, str, str]]:
        """(ip, host, country) for each external peer, named hosts first."""
        out = []
        for ip in self.remote_ips:
            host, country = self.remote_info.get(ip, ("", ""))
            out.append((ip, host, country))
        out.sort(key=lambda t: (not t[1], t[1] or t[0]))
        return out

    @property
    def external_count(self) -> int:
        return sum(1 for c in self.connections if c.is_external)

    @property
    def active_tcp_count(self) -> int:
        return sum(1 for c in self.connections if c.is_active_tcp)

    @property
    def listen_count(self) -> int:
        return sum(1 for c in self.connections if c.is_listening)

    @property
    def udp_count(self) -> int:
        return sum(1 for c in self.connections if c.protocol == "UDP")

    @property
    def remote_ips(self) -> list[str]:
        return sorted({c.remote_ip for c in self.connections if c.is_external})

    @property
    def search_blob(self) -> str:
        hosts = [h for h, _c in self.remote_info.values() if h]
        parts = [self.name, self.exe, *map(str, self.pids), *self.remote_ips, *hosts]
        return " ".join(parts).lower()


class ProcessResolver:
    """PID -> (name, exe, package_sid) with a cache pruned on every scan."""

    def __init__(self, sid_lookup: Callable[[int], str] = get_app_container_sid) -> None:
        self._cache: dict[int, tuple[str, str, str]] = {}
        self._sid_lookup = sid_lookup

    def resolve(self, pid: int) -> tuple[str, str, str]:
        cached = self._cache.get(pid)
        if cached is not None:
            return cached
        name, exe = f"PID {pid}", ""
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                name = proc.name() or name
                try:
                    exe = proc.exe() or ""
                except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    exe = ""
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass
        # Only Store-installed binaries: browsers also sandbox some child
        # processes in AppContainers, and those must stay path-based.
        sid = self._sid_lookup(pid) if exe and is_store_app_path(exe) else ""
        self._cache[pid] = (name, exe, sid)
        return self._cache[pid]

    def prune(self, alive: Iterable[int]) -> None:
        keep = set(alive)
        for pid in list(self._cache):
            if pid not in keep:
                del self._cache[pid]


def group_connections(raw: Iterable, resolver) -> dict[str, ProcessGroup]:
    """Turn psutil `sconn` tuples into per-executable groups."""
    groups: dict[str, ProcessGroup] = {}
    for conn in raw:
        pid = conn.pid
        if not pid:  # None (no permission) or 0 (System Idle / TIME_WAIT leftovers)
            continue
        if conn.status == psutil.CONN_TIME_WAIT:
            continue
        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        family = "IPv6" if conn.family == socket.AF_INET6 else "IPv4"
        local_ip, local_port = (conn.laddr.ip, conn.laddr.port) if conn.laddr else ("", 0)
        remote_ip, remote_port = (conn.raddr.ip, conn.raddr.port) if conn.raddr else ("", 0)

        name, exe, *rest = resolver.resolve(pid)
        sid = rest[0] if rest else ""
        key = normalize_exe(exe) if exe else f"pid:{pid}"
        group = groups.get(key)
        if group is None:
            group = groups[key] = ProcessGroup(key=key, name=name, exe=exe)
        if sid and not group.package_sid:
            group.package_sid = sid
        group.pids.add(pid)
        group.connections.append(
            Connection(
                pid=pid,
                protocol=protocol,
                family=family,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                status=conn.status if protocol == "TCP" else "",
            )
        )
    return groups


class NetworkMonitor:
    def __init__(
        self,
        conn_provider: Callable[[], Iterable] | None = None,
        resolver: ProcessResolver | None = None,
    ) -> None:
        self._provider = conn_provider or (lambda: psutil.net_connections(kind="inet"))
        self._resolver = resolver or ProcessResolver()

    def snapshot(self) -> list[ProcessGroup]:
        try:
            raw = list(self._provider())
        except psutil.AccessDenied as exc:
            raise PermissionError("لا توجد صلاحية لقراءة اتصالات الشبكة") from exc
        groups = group_connections(raw, self._resolver)
        alive = {pid for g in groups.values() for pid in g.pids}
        self._resolver.prune(alive)
        return sorted(groups.values(), key=lambda g: (-g.external_count, g.name.lower()))


class ThroughputMeter:
    """System-wide upload/download rate in bytes per second."""

    def __init__(self, counters: Callable = psutil.net_io_counters, clock: Callable = time.monotonic):
        self._counters = counters
        self._clock = clock
        self._last: tuple[float, int, int] | None = None

    def sample(self) -> tuple[float, float]:
        io = self._counters()
        now = self._clock()
        sent, recv = io.bytes_sent, io.bytes_recv
        if self._last is None:
            self._last = (now, sent, recv)
            return 0.0, 0.0
        t0, s0, r0 = self._last
        self._last = (now, sent, recv)
        dt = max(now - t0, 1e-6)
        return max(sent - s0, 0) / dt, max(recv - r0, 0) / dt
