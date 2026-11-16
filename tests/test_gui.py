"""Offscreen end-to-end tests: real window, real worker threads, dry-run firewall."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QItemSelectionModel, Qt  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from conftest import FakeResolver, tcp, udp  # noqa: E402
from netguard import i18n  # noqa: E402
from netguard.bandwidth import BandwidthTracker  # noqa: E402
from netguard.blocker import BlockManager  # noqa: E402
from netguard.firewall import DryRunFirewall, make_rule_id  # noqa: E402
from netguard.history import HistoryStore  # noqa: E402
from netguard.hostnames import HostResolver  # noqa: E402
from netguard.killswitch import KillSwitch  # noqa: E402
from netguard.monitor import NetworkMonitor, ThroughputMeter  # noqa: E402
from netguard.policies import Policy, PolicyStore  # noqa: E402
from netguard.settings import Settings  # noqa: E402
from netguard.ui.main_window import MainWindow, Services  # noqa: E402
from netguard.ui.theme import apply_theme  # noqa: E402

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
DISCORD = r"C:\Users\me\AppData\Local\Discord\app-1.0.9\Discord.exe"
STEAM = r"C:\Program Files (x86)\Steam\steam.exe"
SPOTIFY = r"C:\Program Files\WindowsApps\SpotifyAB.Spotify_1.2_x64__zpdnekdrzrea0\Spotify.exe"
SID = "S-1-15-2-1234567890-1111111111-2222222222-3333333333-4444444444-555555555-666666666"

RAW = [
    tcp(4120, "192.168.1.5", 51000, "142.250.185.78", 443),
    tcp(4121, "192.168.1.5", 51001, "172.217.18.14", 443),
    tcp(4121, "192.168.1.5", 51002, "142.250.185.99", 443),
    tcp(7788, "192.168.1.5", 52000, "162.159.135.234", 443),
    udp(7788, "192.168.1.5", 50010, "66.22.231.11", 50004),
    tcp(5050, "192.168.1.5", 53000, "35.186.224.25", 443),
    tcp(9001, "0.0.0.0", 27036, status="LISTEN"),
    udp(9001, "0.0.0.0", 27015),
    tcp(4, "192.168.1.5", 445, "192.168.1.20", 50123),
]
RESOLVER = FakeResolver({4120: ("chrome.exe", CHROME, ""), 4121: ("chrome.exe", CHROME, ""),
                         7788: ("Discord.exe", DISCORD, ""), 9001: ("steam.exe", STEAM, ""),
                         5050: ("Spotify.exe", SPOTIFY, SID), 4: ("System", "", "")})
HOSTS = {"142.250.185.78": "www.youtube.com", "172.217.18.14": "i.ytimg.com", "142.250.185.99": "www.google.com",
         "162.159.135.234": "gateway.discord.gg", "35.186.224.25": "audio-ak.spotifycdn.com"}


class IO:
    bytes_sent = 0
    bytes_recv = 0


class FakeApi:
    def __init__(self):
        self.reads = {}

    def enable(self, conn):
        return True

    def read(self, conn):
        n = self.reads[conn.flow_key] = self.reads.get(conn.flow_key, 0) + 1
        base = {"142.250.185.78": 250_000, "162.159.135.234": 9_000}.get(conn.remote_ip, 1_200)
        return n * base, n * base // 25


class InlinePool:
    def submit(self, fn, *args):
        fn(*args)

    def shutdown(self, **kw):
        pass


def wait_until(cond, timeout=5000):
    elapsed = 0
    while not cond() and elapsed < timeout:
        QTest.qWait(50)
        elapsed += 50
    return cond()


def make_window(tmp_path, mode="normal", language="ar", theme="dark"):
    app = QApplication.instance() or QApplication([])
    i18n.set_language(language)
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft if language == "ar" else Qt.LayoutDirection.LeftToRight)
    apply_theme(app, theme)
    fw = DryRunFirewall()
    settings = Settings(mode=mode, language=language, theme=theme, show_countries=True)
    services = Services(
        manager=BlockManager(fw, tmp_path / "state.json"),
        settings=settings,
        settings_path=tmp_path / "settings.json",
        policies=PolicyStore(tmp_path / "policies.json"),
        killswitch=KillSwitch(fw, tmp_path / "ks.json"),
        history=HistoryStore(":memory:"),
        bandwidth=BandwidthTracker(FakeApi()),
        resolver=HostResolver(dns_cache_reader=lambda: HOSTS, ptr_lookup=lambda ip: "",
                              country_fetcher=lambda ips: {ip: "US" for ip in ips}, executor=InlinePool()),
        data_dir=str(tmp_path),
    )
    win = MainWindow(NetworkMonitor(lambda: RAW, RESOLVER), ThroughputMeter(lambda: IO()), services,
                     can_block=True, warnings=["warn_simulation"])
    win.confirm_on_close = False
    win.show()
    assert wait_until(lambda: win.proxy.rowCount() > 0)
    return win, services, fw


@pytest.fixture
def window(tmp_path):
    win, services, fw = make_window(tmp_path)
    yield win, services.manager
    win.close()


@pytest.fixture
def adv(tmp_path):
    win, services, fw = make_window(tmp_path, mode="advanced")
    yield win, services, fw
    win.close()


def select_by_name(win, name):
    for row in range(win.proxy.rowCount()):
        idx = win.proxy.index(row, 1)
        if idx.data() == name:
            win.proc_view.selectionModel().select(
                idx, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)
            return
    raise AssertionError(f"{name} not visible")


def visible_names(win):
    return {win.proxy.index(r, 1).data() for r in range(win.proxy.rowCount())}


def row_of(win, name):
    return next(r for r in range(win.proxy.rowCount()) if win.proxy.index(r, 1).data() == name)


# ------------------------------------------------------------ normal mode --
def test_normal_mode_hides_advanced_parts(window):
    win, _ = window
    assert win.proc_view.isColumnHidden(2) and win.proc_view.isColumnHidden(4)
    assert [win.tabs.isTabVisible(i) for i in range(6)] == [True, True, False, False, False, False]
    assert not win.add_rule_btn.isVisible() and not win.theme_btn.isVisible()


def test_filters(window):
    win, _ = window
    assert visible_names(win) == {"chrome.exe", "Discord.exe", "Spotify.exe", "System"}
    win.only_internet.setChecked(False)
    assert "steam.exe" in visible_names(win)
    win.search.setText("142.250.185.78")
    assert visible_names(win) == {"chrome.exe"}


def test_block_and_unblock_flow(window):
    win, manager = window
    select_by_name(win, "Discord.exe")
    assert win.block_btn.isEnabled() and not win.unblock_btn.isEnabled()
    win.duration.setCurrentIndex(0)  # 1 minute
    win.block_selected()
    assert wait_until(lambda: manager.is_blocked_exe(DISCORD))
    assert wait_until(lambda: win.blocked_model.rowCount() == 1)
    assert win.tabs.tabText(0) == "البرامج المحظورة (1)"
    assert win.blocked_model.index(0, 4).data() in ("01:00", "00:59")
    win.sig_scan_now.emit()
    QTest.qWait(300)
    assert [g.name for g in win.selected_groups()] == ["Discord.exe"]
    assert win.proxy.index(row_of(win, "Discord.exe"), 0).data() == "محظور"
    assert wait_until(lambda: win.unblock_btn.isEnabled())
    win.unblock_selected_processes()
    assert wait_until(lambda: not manager.is_blocked_exe(DISCORD))


def test_protected_process_cannot_be_blocked(window):
    win, _ = window
    select_by_name(win, "System")
    assert not win.block_btn.isEnabled()


def test_store_app_is_blocked_by_package(window):
    win, manager = window
    select_by_name(win, "Spotify.exe")
    win.block_selected()
    assert wait_until(lambda: manager.is_blocked_exe(SPOTIFY))
    assert manager.entries()[0].package_sid == SID


# ---------------------------------------------------------- advanced mode --
def test_mode_switch_and_persistence(window, tmp_path):
    win, _ = window
    win.mode_advanced.click()
    assert not win.proc_view.isColumnHidden(2)
    assert all(win.tabs.isTabVisible(i) for i in range(6))
    assert Settings.load(tmp_path / "settings.json").mode == "advanced"
    win.mode_normal.click()
    assert win.proc_view.isColumnHidden(2)


def test_advanced_shows_rates_and_destinations(adv):
    win, _, _ = adv
    win.sig_scan_now.emit()
    assert wait_until(lambda: "youtube" in (win.proxy.index(row_of(win, "chrome.exe"), 4).data() or ""))
    assert wait_until(lambda: "(US)" in win.proxy.index(row_of(win, "chrome.exe"), 4).data())
    assert wait_until(lambda: "KB/s" in win.proxy.index(row_of(win, "chrome.exe"), 2).data()
                      or "MB/s" in win.proxy.index(row_of(win, "chrome.exe"), 2).data())
    win.search.setText("discord.gg")
    assert visible_names(win) == {"Discord.exe"}


def test_language_switch_live(adv):
    win, services, _ = adv
    assert win.block_btn.text().endswith("حظر الإنترنت")
    win.toggle_language()
    assert QApplication.instance().layoutDirection() == Qt.LayoutDirection.LeftToRight
    assert win.block_btn.text().endswith("Block internet")
    assert win.proc_model.headerData(1, Qt.Orientation.Horizontal) == "Program"
    assert win.tabs.tabText(2) == "Rules && schedules"
    assert win.duration.itemText(0) == "1 minute"
    assert services.settings.language == "en"
    win.toggle_language()
    assert win.block_btn.text().endswith("حظر الإنترنت")


def test_theme_toggle(adv):
    win, services, _ = adv
    from netguard.ui import theme
    win.toggle_theme()
    assert theme.current_name() == "light" and services.settings.theme == "light"
    win.toggle_theme()
    assert theme.current_name() == "dark"


def test_scheduled_rule_blocks_and_releases(adv):
    win, services, fw = adv
    policy = Policy(exe=STEAM, name="steam.exe")
    services.policies.upsert(policy)
    win.rules_tab.refresh()
    win.sig_sync_policies.emit()
    assert wait_until(lambda: services.manager.is_blocked_exe(STEAM))
    assert wait_until(lambda: win.blocked_model.rowCount() == 1)
    assert "قاعدة" in win.blocked_model.index(0, 2).data()
    services.policies.set_enabled(policy.id, False)
    win.sig_sync_policies.emit()
    assert wait_until(lambda: not services.manager.is_blocked_exe(STEAM))
    events = [e.kind for e in services.history.recent_events()]
    assert events[:2] == ["rule_off", "rule_on"]


def test_killswitch_from_ui(adv, monkeypatch):
    win, services, fw = adv
    select_by_name(win, "Discord.exe")
    win.kill_tab.add_selected()
    assert services.settings.kill_switch_allow == [DISCORD]
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: QMessageBox.StandardButton.Yes)
    win.request_killswitch(True)
    assert wait_until(lambda: services.killswitch.active)
    assert wait_until(lambda: win.kill_alert.isVisible())
    assert set(fw.policy.values()) == {"Block"} and fw.list_allow_ids() == {make_rule_id(DISCORD)}
    win.request_killswitch(False)
    assert wait_until(lambda: not services.killswitch.active)
    assert wait_until(lambda: not win.kill_alert.isVisible())
    assert set(fw.policy.values()) == {"NotConfigured"}


def test_close_cleans_everything(tmp_path):
    win, services, fw = make_window(tmp_path, mode="advanced")
    select_by_name(win, "chrome.exe")
    win.block_selected()
    assert wait_until(lambda: services.manager.is_blocked_exe(CHROME))
    win.close()
    assert fw.list_rule_names() == set()


# ----------------------------------------------------------- screenshots --
@pytest.mark.parametrize("mode,language,theme", [("normal", "ar", "dark"), ("advanced", "ar", "dark"),
                                                 ("advanced", "en", "light")])
def test_screenshot(tmp_path, mode, language, theme):
    out = os.environ.get("NETGUARD_SHOT_DIR")
    win, services, _ = make_window(tmp_path, mode, language, theme)
    try:
        services.policies.upsert(Policy(exe=STEAM, name="steam.exe", kind="schedule", days=[3, 4],
                                        start=23 * 60, end=6 * 60))
        win.rules_tab.refresh()
        select_by_name(win, "chrome.exe")
        win.duration.setCurrentIndex(6)
        win.block_selected()
        QTest.qWait(500)
        for _ in range(3):  # rates need two samples
            win.sig_scan_now.emit()
            QTest.qWait(300)
        select_by_name(win, "Discord.exe")
        win.tabs.setCurrentIndex(0)
        QTest.qWait(300)
        if out:
            win.grab().save(os.path.join(out, f"{mode}-{language}-{theme}.png"))
            if mode == "advanced" and language == "ar":
                for index, name in ((2, "rules"), (3, "killswitch"), (4, "history"), (5, "settings")):
                    win.tabs.setCurrentIndex(index)
                    QTest.qWait(200)
                    win.grab().save(os.path.join(out, f"tab-{name}.png"))
    finally:
        win.close()
