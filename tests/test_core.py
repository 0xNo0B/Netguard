import json
import socket

import pytest

from conftest import FakeResolver, tcp, udp
from netguard.blocker import BlockManager
from netguard.firewall import (
    CommandResult,
    DryRunFirewall,
    FirewallError,
    WindowsFirewall,
    make_rule_id,
    parse_rule_id,
    rule_names,
    validate_program_path,
)
from netguard.monitor import NetworkMonitor, ThroughputMeter, group_connections, is_local_ip
from netguard.tcp_killer import MIB_TCPROW, build_row, close_tcp_connections

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
STEAM = r"C:\Program Files (x86)\Steam\steam.exe"


# ---------------------------------------------------------------- monitor --
def test_groups_by_executable_and_counts():
    raw = [
        tcp(10, "192.168.1.5", 50000, "142.250.1.1", 443),
        tcp(11, "192.168.1.5", 50001, "142.250.1.2", 443),          # 2nd chrome pid
        tcp(11, "127.0.0.1", 50002, "127.0.0.1", 9222),              # loopback, not external
        tcp(20, "0.0.0.0", 27036, status="LISTEN"),
        udp(20, "0.0.0.0", 27015),
        udp(20, "192.168.1.5", 3478, "203.0.113.9", 3478),
        tcp(0, "192.168.1.5", 50003, "1.1.1.1", 443, status="TIME_WAIT"),  # skipped
        tcp(None, "192.168.1.5", 50004, "1.1.1.1", 443),                  # skipped
        tcp(30, "192.168.1.5", 50005, "8.8.8.8", 443),                    # protected
    ]
    resolver = FakeResolver({10: ("chrome.exe", CHROME), 11: ("chrome.exe", CHROME),
                             20: ("steam.exe", STEAM), 30: ("System", "")})
    groups = group_connections(raw, resolver)
    chrome = next(g for g in groups.values() if g.name == "chrome.exe")
    steam = next(g for g in groups.values() if g.name == "steam.exe")
    system = groups["pid:30"]

    assert chrome.pids == {10, 11}
    assert chrome.external_count == 2
    assert chrome.active_tcp_count == 3
    assert chrome.remote_ips == ["142.250.1.1", "142.250.1.2"]
    assert steam.listen_count == 1 and steam.udp_count == 2 and steam.external_count == 1
    assert not system.blockable and system.exe == ""
    assert len(groups) == 3


def test_snapshot_sorted_by_external_traffic():
    raw = [tcp(1, "10.0.0.2", 1, "9.9.9.9", 443), tcp(2, "10.0.0.2", 2, "9.9.9.9", 443),
           tcp(2, "10.0.0.2", 3, "9.9.9.8", 443)]
    mon = NetworkMonitor(lambda: raw, FakeResolver({1: ("a.exe", r"C:\a.exe"), 2: ("b.exe", r"C:\b.exe")}))
    assert [g.name for g in mon.snapshot()] == ["b.exe", "a.exe"]


@pytest.mark.parametrize("ip,local", [("127.0.0.1", True), ("::1", True), ("0.0.0.0", True),
                                      ("::ffff:127.0.0.1", True), ("fe80::1%12", False),
                                      ("8.8.8.8", False), ("garbage", False)])
def test_is_local_ip(ip, local):
    assert is_local_ip(ip) is local


def test_throughput_meter():
    class IO:
        def __init__(self, s, r):
            self.bytes_sent, self.bytes_recv = s, r
    samples = iter([IO(0, 0), IO(1000, 4000)])
    times = iter([0.0, 2.0])
    meter = ThroughputMeter(lambda: next(samples), lambda: next(times))
    assert meter.sample() == (0.0, 0.0)
    assert meter.sample() == (500.0, 2000.0)


# --------------------------------------------------------------- firewall --
def test_rule_id_is_stable_and_case_insensitive_on_windows_paths():
    rid = make_rule_id(CHROME)
    assert len(rid) == 12
    assert make_rule_id(CHROME) == rid
    out_name, in_name = rule_names(rid)
    assert parse_rule_id(out_name) == rid and parse_rule_id(in_name) == rid
    assert parse_rule_id("Some other rule") is None


class Recorder:
    def __init__(self, codes=None):
        self.commands = []
        self.codes = codes or {}

    def __call__(self, cmd):
        self.commands.append(cmd)
        for needle, code in self.codes.items():
            if needle in cmd:
                return CommandResult(code, "boom" if code else "", "")
        return CommandResult(0, "", "")


def test_windows_add_builds_quoted_netsh_commands():
    rec = Recorder()
    fw = WindowsFirewall(runner=rec, system_root=r"C:\Windows")
    rid = make_rule_id(CHROME)
    fw.add_block(rid, CHROME)
    assert len(rec.commands) == 2
    out_cmd, in_cmd = rec.commands
    assert out_cmd.startswith('"C:\\Windows\\System32\\netsh.exe" advfirewall firewall add rule')
    assert f'name="NetGuard-{rid}-Out"' in out_cmd and "dir=out" in out_cmd
    assert f'program="{CHROME}"' in out_cmd and "action=block" in out_cmd
    assert "dir=in" in in_cmd


@pytest.mark.parametrize("bad", ['C:\\a"b.exe', "relative\\x.exe", "", "C:\\x.exe\n&calc"])
def test_rejects_unsafe_paths(bad):
    with pytest.raises(FirewallError):
        validate_program_path(bad)


def test_add_rolls_back_when_second_rule_fails():
    rec = Recorder({"dir=in": 1})
    fw = WindowsFirewall(runner=rec, system_root=r"C:\Windows")
    rid = make_rule_id(CHROME)
    with pytest.raises(FirewallError):
        fw.add_block(rid, CHROME)
    assert "delete rule" in rec.commands[-1] and f"NetGuard-{rid}-Out" in rec.commands[-1]


def test_remove_verifies_rule_is_gone():
    fw_ok = WindowsFirewall(runner=Recorder({"show rule": 1}))   # show -> 1 = not found
    fw_ok.remove_block("a" * 12)
    fw_bad = WindowsFirewall(runner=Recorder({"show rule": 0}))  # still exists
    with pytest.raises(FirewallError):
        fw_bad.remove_block("a" * 12)


def test_powershell_listing_and_status_parsing():
    rid = "0123456789ab"

    def runner(cmd):
        assert "-EncodedCommand" in cmd
        import base64
        script = base64.b64decode(cmd.rsplit(" ", 1)[1]).decode("utf-16-le")
        if "Get-NetFirewallRule" in script:
            return CommandResult(0, f"NetGuard-{rid}-Out\r\nNetGuard-{rid}-In\r\nNetGuard-bogus\r\n", "")
        return CommandResult(0, "Domain=True\r\nPrivate=True\r\nPublic=False\r\n", "")

    fw = WindowsFirewall(runner=runner)
    assert fw.list_rule_ids() == {rid}
    assert fw.firewall_status() == {"Domain": True, "Private": True, "Public": False}


def test_invalid_rule_id_rejected():
    with pytest.raises(FirewallError):
        DryRunFirewall().add_block('x" & calc', CHROME)


# ---------------------------------------------------------------- blocker --
def test_block_expire_and_unblock(tmp_path, clock):
    fw = DryRunFirewall()
    mgr = BlockManager(fw, tmp_path / "s.json", clock=clock)
    entry = mgr.block(CHROME, "chrome.exe", 60)
    assert fw.list_rule_ids() == {entry.rule_id}
    assert mgr.is_blocked_exe(CHROME)
    clock.advance(30)
    assert mgr.expire_due() == []
    assert mgr.entries()[0].remaining(clock()) == 30
    clock.advance(31)
    expired = mgr.expire_due()
    assert [e.name for e in expired] == ["chrome.exe"]
    assert fw.list_rule_ids() == set() and mgr.entries() == []


def test_reblock_resets_timer_without_duplicate_rule(tmp_path, clock):
    mgr = BlockManager(DryRunFirewall(), tmp_path / "s.json", clock=clock)
    mgr.block(CHROME, "chrome.exe", 60)
    clock.advance(50)
    mgr.block(CHROME, "chrome.exe", None)
    clock.advance(1000)
    assert mgr.expire_due() == [] and len(mgr.entries()) == 1


def test_restore_after_crash(tmp_path, clock):
    path = tmp_path / "s.json"
    fw = DryRunFirewall()
    mgr = BlockManager(fw, path, clock=clock)
    keep = mgr.block(CHROME, "chrome.exe", 600)
    gone = mgr.block(STEAM, "steam.exe", 10)
    fw.add_block("ffffffffffff", r"C:\orphan.exe")     # unknown leftover rule
    fw.remove_block(keep.rule_id)                       # rule deleted behind our back
    clock.advance(20)

    mgr2 = BlockManager(fw, path, clock=clock)          # "app restarted"
    report = mgr2.restore()
    assert [e.rule_id for e in report.restored] == [keep.rule_id]
    assert report.expired_removed == ["steam.exe"]
    assert report.orphans_removed == ["ffffffffffff"]
    assert fw.list_rule_ids() == {keep.rule_id}         # re-applied
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert [b["rule_id"] for b in saved["blocks"]] == [keep.rule_id]
    assert gone.rule_id not in fw.list_rule_ids()


def test_failed_auto_unblock_is_retried_later(tmp_path, clock):
    class Flaky(DryRunFirewall):
        fail = True

        def remove_block(self, rule_id):
            if self.fail:
                raise FirewallError("netsh busy")
            super().remove_block(rule_id)

    fw = Flaky()
    mgr = BlockManager(fw, None, clock=clock)
    mgr.block(CHROME, "chrome.exe", 5)
    clock.advance(6)
    assert mgr.expire_due() == []
    fw.fail = False
    clock.advance(1)
    assert mgr.expire_due() == []          # waiting for retry delay
    clock.advance(30)
    assert len(mgr.expire_due()) == 1


def test_block_requires_exe(clock):
    mgr = BlockManager(DryRunFirewall(), None, clock=clock)
    with pytest.raises(FirewallError):
        mgr.block("", "System", 60)


# ------------------------------------------------------------- tcp killer --
def test_build_row_byte_order():
    row = build_row("192.168.1.5", 50000, "142.250.1.1", 443)
    raw = bytes(row)
    assert raw[4:8] == socket.inet_aton("192.168.1.5")
    assert raw[8:10] == (50000).to_bytes(2, "big")
    assert raw[12:16] == socket.inet_aton("142.250.1.1")
    assert raw[16:18] == (443).to_bytes(2, "big")
    assert row.dwState == 12


def test_close_tcp_connections_filters_correctly():
    conns = [
        tcp(10, "192.168.1.5", 50000, "142.250.1.1", 443),
        tcp(10, "127.0.0.1", 50001, "127.0.0.1", 9222),      # loopback: keep
        tcp(10, "0.0.0.0", 80, status="LISTEN"),              # listener: keep
        tcp(99, "192.168.1.5", 50002, "1.1.1.1", 443),        # other pid
    ]
    calls = []

    def fake_set(ptr):
        row = ptr._obj  # ctypes.byref() wrapper -> the MIB_TCPROW
        assert isinstance(row, MIB_TCPROW)
        calls.append(socket.inet_ntoa(row.dwRemoteAddr.to_bytes(4, "little")))
        return 0

    assert close_tcp_connections([10], lambda: conns, fake_set) == (1, 0)
    assert calls == ["142.250.1.1"]
