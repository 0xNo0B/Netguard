import socket
import sys
from collections import namedtuple
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

Addr = namedtuple("Addr", "ip port")
SConn = namedtuple("SConn", "fd family type laddr raddr status pid")


def tcp(pid, lip, lport, rip=None, rport=None, status="ESTABLISHED", v6=False):
    return SConn(-1, socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_STREAM,
                 Addr(lip, lport), Addr(rip, rport) if rip else (), status, pid)


def udp(pid, lip, lport, rip=None, rport=None):
    return SConn(-1, socket.AF_INET, socket.SOCK_DGRAM, Addr(lip, lport),
                 Addr(rip, rport) if rip else (), "NONE", pid)


class FakeResolver:
    def __init__(self, table):
        self.table = table

    def resolve(self, pid):
        return self.table.get(pid, (f"PID {pid}", ""))

    def prune(self, alive):
        pass


class FakeClock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


@pytest.fixture
def clock():
    return FakeClock()
