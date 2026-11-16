import ast
import base64
import datetime as dt
import re
import socket
from pathlib import Path

import pytest

from conftest import FakeResolver, tcp
from netguard import i18n
from netguard.autostart import build_register_script
from netguard.bandwidth import TCP_ESTATS_DATA_ROD_v0, BandwidthTracker, make_row
from netguard.blocker import BlockManager, DesiredBlock
from netguard.firewall import (
    CommandResult,
    DryRunFirewall,
    FirewallError,
    WindowsFirewall,
    make_rule_id,
    parse_rule_name,
    ps_quote,
)
from netguard.history import HistoryStore
from netguard.hostnames import HostResolver, is_public_ip
from netguard.killswitch import KillSwitch
from netguard.monitor import NetworkMonitor, group_connections
from netguard.policies import Policy, PolicyStore, desired_blocks
from netguard.settings import Settings
from netguard.strings import STRINGS

GAME = r"C:\Games\game.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
STORE = r"C:\Program Files\WindowsApps\SpotifyAB.Spotify_1.2.3_x64__zpdnekdrzrea0\Spotify.exe"
SID = "S-1-15-2-1234567890-1111111111-2222222222-3333333333-4444444444-555555555-666666666"


def at(weekday: int, hh: int, mm: int = 0) -> dt.datetime:
    # 2026-11-09 is a Monday (weekday 0)
    return dt.datetime(2026, 11, 9 + weekday, hh, mm)


# ---------------------------------------------------------------- policies --
def test_always_policy():
    p = Policy(exe=GAME, name="game.exe")
    assert p.is_active(at(3, 15))
    p.enabled = False
    assert not p.is_active(at(3, 15))


def test_schedule_same_day_window():
    p = Policy(exe=GAME, name="g", kind="schedule", days=[0, 1, 2], start=9 * 60, end=17 * 60)
    assert p.is_active(at(0, 9))
    assert p.is_active(at(2, 16, 59))
    assert not p.is_active(at(0, 17))
    assert not p.is_active(at(4, 12))       # Friday not selected


def test_schedule_crossing_midnight_belongs_to_start_day():
    p = Policy(exe=GAME, name="g", kind="schedule", days=[6], start=23 * 60, end=6 * 60)  # Sunday night
    assert p.is_active(at(6, 23, 30))        # Sunday 23:30
    assert p.is_active(dt.datetime(2026, 11, 16, 5, 59))  # Monday 05:59 (continuation)
    assert not p.is_active(dt.datetime(2026, 11, 16, 6, 0))
    assert not p.is_active(at(0, 23, 30))    # Monday night not selected
    assert not p.is_active(at(6, 5))         # Sunday early morning: Saturday not selected


def test_schedule_equal_times_means_whole_day():
    p = Policy(exe=GAME, name="g", kind="schedule", days=[4], start=0, end=0)
    assert p.is_active(at(4, 0)) and p.is_active(at(4, 23, 59)) and not p.is_active(at(5, 1))


def test_desired_blocks_groups_policies_per_program(tmp_path):
    store = PolicyStore(tmp_path / "p.json")
    a = Policy(exe=GAME, name="game.exe")
    b = Policy(exe=GAME.upper(), name="game.exe", kind="schedule", days=[0], start=60, end=120)
    c = Policy(exe=CHROME, name="chrome.exe", enabled=False)
    for p in (a, b, c):
        store.upsert(p)
    desired = desired_blocks(PolicyStore(tmp_path / "p.json").all(), at(0, 1, 30))  # reload from disk
    assert list(desired) == [make_rule_id(GAME)]
    assert set(desired[make_rule_id(GAME)].policy_ids) == {a.id, b.id}


# ------------------------------------------------------------- blocker+rules --
def test_policy_and_manual_reasons(tmp_path, clock):
    fw = DryRunFirewall()
    mgr = BlockManager(fw, tmp_path / "s.json", clock=clock)
    rid = make_rule_id(GAME)
    want = {rid: DesiredBlock(GAME, "game.exe", "", ("p1",))}

    res = mgr.sync_policies(want)
    assert [e.name for e in res.added] == ["game.exe"] and rid in fw.list_rule_ids()

    mgr.block(GAME, "game.exe", 60)                 # manual on top of the rule
    assert mgr.unblock(rid).still_blocked           # rule keeps it blocked
    assert rid in fw.list_rule_ids()

    res = mgr.sync_policies({})                     # rule window ends
    assert [e.name for e in res.removed] == ["game.exe"] and rid not in fw.list_rule_ids()


def test_manual_block_survives_rule_end(tmp_path, clock):
    fw = DryRunFirewall()
    mgr = BlockManager(fw, None, clock=clock)
    rid = make_rule_id(GAME)
    mgr.sync_policies({rid: DesiredBlock(GAME, "game.exe", "", ("p1",))})
    mgr.block(GAME, "game.exe", 600)
    mgr.sync_policies({})
    assert rid in fw.list_rule_ids()                # manual still applies
    clock.advance(601)
    assert [e.name for e in mgr.expire_due()] == ["game.exe"]
    assert rid not in fw.list_rule_ids()


def test_expiry_does_not_remove_rule_owned_block(tmp_path, clock):
    fw = DryRunFirewall()
    mgr = BlockManager(fw, None, clock=clock)
    rid = make_rule_id(GAME)
    mgr.block(GAME, "game.exe", 10)
    mgr.sync_policies({rid: DesiredBlock(GAME, "game.exe", "", ("p1",))})
    clock.advance(11)
    assert mgr.expire_due() == []
    entry = mgr.entries()[0]
    assert not entry.manual and entry.policies == ["p1"] and rid in fw.list_rule_ids()


def test_remove_all_drops_everything(clock):
    fw = DryRunFirewall()
    mgr = BlockManager(fw, None, clock=clock)
    mgr.block(CHROME, "chrome.exe", None)
    mgr.sync_policies({make_rule_id(GAME): DesiredBlock(GAME, "game.exe", "", ("p",))})
    assert mgr.remove_all() == [] and fw.list_rule_names() == set()


# --------------------------------------------------------------- firewall --
class Recorder:
    def __init__(self, stdout=""):
        self.commands = []
        self.stdout = stdout

    def __call__(self, cmd):
        self.commands.append(cmd)
        if "show rule" in cmd:
            return CommandResult(1, "", "")
        return CommandResult(0, self.stdout, "")


def decode_ps(cmd: str) -> str:
    return base64.b64decode(cmd.rsplit(" ", 1)[1]).decode("utf-16-le")


def test_store_app_rules_use_package_sid():
    rec = Recorder()
    WindowsFirewall(runner=rec).add_block(make_rule_id(STORE), STORE, SID)
    script = decode_ps(rec.commands[0])
    assert f"-Package '{SID}'" in script and "-Direction Outbound" in script and "-Direction Inbound" in script
    assert "-Program" not in script


@pytest.mark.parametrize("bad", ["S-1-5-21-1", "S-1-15-2-1'; calc", ""])
def test_bad_package_sid_rejected(bad):
    with pytest.raises(FirewallError):
        WindowsFirewall(runner=Recorder()).add_block("0123456789ab", STORE, bad or "x")


def test_allow_rule_and_policy_commands():
    rec = Recorder()
    fw = WindowsFirewall(runner=rec, system_root=r"C:\Windows")
    rid = make_rule_id(CHROME)
    fw.add_allow(rid, CHROME)
    assert f'name="NetGuard-{rid}-Allow"' in rec.commands[0] and "action=allow" in rec.commands[0]
    assert "dir=out" in rec.commands[0]
    assert fw.build_set_policy_script({"Public": "Block", "Domain": "Block"}) == (
        "Set-NetFirewallProfile -Name Domain -DefaultOutboundAction Block; "
        "Set-NetFirewallProfile -Name Public -DefaultOutboundAction Block")
    with pytest.raises(FirewallError):
        fw.build_set_policy_script({"Public": "Block; calc"})


def test_get_outbound_policy_parsing():
    fw = WindowsFirewall(runner=Recorder("Domain=NotConfigured\r\nPrivate=Allow\r\nPublic=Block\r\n"))
    assert fw.get_outbound_policy() == {"Domain": "NotConfigured", "Private": "Allow", "Public": "Block"}


def test_parse_rule_name_kinds():
    assert parse_rule_name("NetGuard-0123456789ab-Allow") == ("0123456789ab", "Allow")
    assert parse_rule_name("NetGuard-0123456789ab-Out") == ("0123456789ab", "Out")
    assert parse_rule_name("NetGuard-zz-Out") is None


def test_ps_quote():
    assert ps_quote("C:\\Bob's App\\a.exe") == "'C:\\Bob''s App\\a.exe'"
    with pytest.raises(FirewallError):
        ps_quote("a\nb")


# ------------------------------------------------------------- kill switch --
def test_killswitch_enable_disable_restores_original(tmp_path):
    fw = DryRunFirewall()
    fw.set_outbound_policy({"Domain": "Allow", "Private": "NotConfigured", "Public": "Block"})
    ks = KillSwitch(fw, tmp_path / "ks.json")
    assert ks.enable([CHROME]) == []
    assert set(fw.policy.values()) == {"Block"}
    assert fw.list_allow_ids() == {make_rule_id(CHROME)}

    ks.update_allowed([CHROME, GAME])
    assert fw.list_allow_ids() == {make_rule_id(CHROME), make_rule_id(GAME)}

    ks.disable()
    assert fw.policy == {"Domain": "Allow", "Private": "NotConfigured", "Public": "Block"}
    assert fw.list_allow_ids() == set() and not ks.active


def test_killswitch_survives_crash(tmp_path):
    fw = DryRunFirewall()
    KillSwitch(fw, tmp_path / "ks.json").enable([CHROME])
    fw.remove_allow(make_rule_id(CHROME))                       # rule lost meanwhile
    fw.set_outbound_policy({"Domain": "Allow", "Private": "Allow", "Public": "Allow"})
    ks2 = KillSwitch(fw, tmp_path / "ks.json")                  # app restarted
    assert ks2.active and ks2.restore() == []
    assert set(fw.policy.values()) == {"Block"} and fw.list_allow_ids() == {make_rule_id(CHROME)}
    ks2.disable()
    assert set(fw.policy.values()) == {"NotConfigured"}         # true original, saved before the change


def test_killswitch_rolls_back_when_policy_change_fails(tmp_path):
    class Broken(DryRunFirewall):
        def set_outbound_policy(self, policy):
            raise FirewallError("denied")

    fw = Broken()
    ks = KillSwitch(fw, tmp_path / "ks.json")
    with pytest.raises(FirewallError):
        ks.enable([CHROME])
    assert not ks.active and fw.list_allow_ids() == set()


def test_killswitch_cleans_leftover_allow_rules(tmp_path):
    fw = DryRunFirewall()
    fw.add_allow("0123456789ab", CHROME)
    KillSwitch(fw, tmp_path / "ks.json").restore()
    assert fw.list_allow_ids() == set()


# ---------------------------------------------------------------- history --
def test_history_events_and_usage(clock):
    h = HistoryStore(":memory:", clock=clock)
    h.log_event("block", "game.exe", GAME, "15m")
    clock.advance(5)
    h.log_event("unblock", "game.exe", GAME)
    assert [e.kind for e in h.recent_events()] == ["unblock", "block"]
    assert [e.kind for e in h.recent_events(kind="block")] == ["block"]

    h.add_usage([("k1", "chrome.exe", CHROME, 1000, 10), ("k2", "game.exe", GAME, 50, 50)])
    h.add_usage([("k1", "chrome.exe", CHROME, 500, 5), ("k3", "idle.exe", "", 0, 0)])
    top = h.top_usage(days=1)
    assert [(r.name, r.bytes_in, r.bytes_out) for r in top] == [("chrome.exe", 1500, 15), ("game.exe", 50, 50)]

    clock.advance(40 * 86400)
    h.prune(30)
    assert h.recent_events() == [] and h.top_usage(days=1) == []
    with pytest.raises(ValueError):
        h.log_event("bogus")


# --------------------------------------------------------------- bandwidth --
def test_estats_struct_layout_matches_header():
    assert TCP_ESTATS_DATA_ROD_v0.DataBytesOut.offset == 0
    assert TCP_ESTATS_DATA_ROD_v0.DataBytesIn.offset == 16
    assert TCP_ESTATS_DATA_ROD_v0.ThruBytesAcked.offset == 72
    assert TCP_ESTATS_DATA_ROD_v0.ThruBytesReceived.offset == 88
    import ctypes
    assert ctypes.sizeof(TCP_ESTATS_DATA_ROD_v0) == 96


def test_make_row_ipv4_and_ipv6():
    groups = group_connections([tcp(1, "10.0.0.2", 50000, "1.2.3.4", 443),
                                tcp(1, "2001:db8::2", 50001, "2001:db8::1", 443, v6=True)],
                               FakeResolver({1: ("a.exe", r"C:\a.exe")}))
    c4, c6 = sorted(next(iter(groups.values())).connections, key=lambda c: c.family)
    r4 = make_row(c4)
    assert bytes(r4)[4:8] == socket.inet_aton("10.0.0.2") and r4.dwState == 5
    r6 = make_row(c6)
    assert bytes(r6.RemoteAddr) == socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    assert r6.dwRemotePort == socket.htons(443)


def test_bandwidth_tracker_rates():
    counters = {}

    class FakeApi:
        enabled = []

        def enable(self, conn):
            self.enabled.append(conn.flow_key)
            return True

        def read(self, conn):
            return counters[conn.remote_ip]

    t = [0.0]
    tracker = BandwidthTracker(FakeApi(), clock=lambda: t[0])
    mon = NetworkMonitor(lambda: [tcp(1, "10.0.0.2", 1, "1.1.1.1", 443), tcp(1, "10.0.0.2", 2, "8.8.8.8", 443)],
                         FakeResolver({1: ("a.exe", r"C:\a.exe")}))
    counters.update({"1.1.1.1": (1000, 100), "8.8.8.8": (0, 0)})
    groups = mon.snapshot()
    tracker.update(groups)
    assert groups[0].rate_down == 0
    t[0] = 2.0
    counters.update({"1.1.1.1": (5000, 300), "8.8.8.8": (2000, 100)})
    groups = mon.snapshot()
    tracker.update(groups)
    g = groups[0]
    assert (g.bytes_down, g.bytes_up) == (6000, 300)
    assert (g.rate_down, g.rate_up) == (3000.0, 150.0)
    assert len(FakeApi.enabled) == 2        # enabled once per connection


# --------------------------------------------------------------- hostnames --
class InlinePool:
    def submit(self, fn, *args):
        fn(*args)

    def shutdown(self, **kw):
        pass


def test_resolver_prefers_dns_cache_then_ptr_and_countries():
    calls = []
    r = HostResolver(
        dns_cache_reader=lambda: {"142.250.1.1": "www.youtube.com"},
        ptr_lookup=lambda ip: "dns.google" if ip == "8.8.8.8" else "",
        country_fetcher=lambda ips: calls.append(list(ips)) or {ip: "US" for ip in ips},
        executor=InlinePool(),
    )
    r.countries_enabled = True
    assert r.lookup("142.250.1.1") == ("www.youtube.com", "")  # country fetched in background
    assert r.lookup("142.250.1.1") == ("www.youtube.com", "US")
    r.lookup("8.8.8.8")
    assert r.lookup("8.8.8.8") == ("dns.google", "US")
    assert r.lookup("192.168.1.1")[1] == ""                      # private: never sent
    assert all(is_public_ip(ip) for batch in calls for ip in batch)


def test_country_failures_are_not_retried_immediately():
    attempts = []
    r = HostResolver(dns_cache_reader=lambda: {}, ptr_lookup=lambda ip: "",
                     country_fetcher=lambda ips: attempts.append(ips) or {}, executor=InlinePool())
    r.countries_enabled = True
    r.lookup("9.9.9.9")
    r.lookup("9.9.9.9")
    assert len(attempts) == 1


# ---------------------------------------------------------------- settings --
def test_settings_roundtrip_and_validation(tmp_path):
    path = tmp_path / "settings.json"
    s = Settings(mode="advanced", language="en", theme="light", kill_switch_allow=[CHROME])
    s.save(path)
    loaded = Settings.load(path)
    assert (loaded.mode, loaded.language, loaded.theme, loaded.kill_switch_allow) == \
        ("advanced", "en", "light", [CHROME])
    path.write_text('{"mode": "weird", "scan_interval_s": 999, "unknown": 1}', encoding="utf-8")
    loaded = Settings.load(path)
    assert loaded.mode == "normal" and loaded.scan_interval_s == 30


def test_autostart_script_quotes_paths():
    script = build_register_script(r"C:\Users\Bob's PC\NetGuard.exe", "--minimized")
    assert "-Execute 'C:\\Users\\Bob''s PC\\NetGuard.exe'" in script
    assert "-RunLevel Highest" in script and "-AllowStartIfOnBatteries" in script
    assert "-ExecutionTimeLimit ([TimeSpan]::Zero)" in script


# -------------------------------------------------------------------- i18n --
SRC = Path(__file__).resolve().parents[1] / "netguard"
KEY_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def _string_constants():
    for path in SRC.rglob("*.py"):
        if path.name == "strings.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                args = node.args
                if name in ("tr", "item") and args and isinstance(args[0], ast.Constant):
                    yield args[0].value
                if name == "bind" and len(args) > 1 and isinstance(args[1], ast.Constant):
                    yield args[1].value
            if isinstance(node, ast.Assign) and any(getattr(t, "id", "") in
                                                    ("HEADER_KEYS", "DURATIONS", "PERIODS", "FILTERS",
                                                     "EVENT_KEYS", "_DAY_KEYS") for t in node.targets):
                for sub in ast.walk(node.value):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and "_" in sub.value \
                            and KEY_RE.match(sub.value) and sub.value not in ("killswitch_on", "killswitch_off",
                                                                              "rule_on", "rule_off"):
                        yield sub.value


def test_every_used_key_is_translated():
    used = {k for k in _string_constants() if isinstance(k, str) and KEY_RE.match(k)}
    missing = sorted(used - STRINGS.keys())
    assert not missing, missing


def test_translations_are_complete_and_formats_match():
    for key, (ar, en) in STRINGS.items():
        assert ar and en, key
        assert set(re.findall(r"{(\w+)}", ar)) == set(re.findall(r"{(\w+)}", en)), key


def test_tr_switches_language():
    i18n.set_language("en")
    assert i18n.tr("msg_blocked", names="x") == "Blocked: x"
    i18n.set_language("ar")
    assert i18n.tr("msg_blocked", names="x") == "تم حظر: x"
    assert i18n.tr("no_such_key") == "no_such_key"
