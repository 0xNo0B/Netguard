"""Firewall backends.

WindowsFirewall drives Windows Defender Firewall:
  * netsh (fast) to add / delete / check program rules,
  * PowerShell (locale-independent output) for Store-app (package SID) rules,
    listing our rules, and reading / changing profile defaults (kill switch).

Rule names (all start with RULE_PREFIX so leftovers can be found safely):
  NetGuard-<id>-Out / NetGuard-<id>-In   block rules for one program
  NetGuard-<id>-Allow                    kill-switch exception for one program
Block rules always win over allow rules in Windows Firewall.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import ntpath
import os
import re
import subprocess
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable

from .config import IS_WINDOWS, RULE_PREFIX, normalize_exe

log = logging.getLogger(__name__)

CREATE_NO_WINDOW = 0x08000000
RULE_ID_LEN = 12
_RULE_NAME_RE = re.compile(rf"^{re.escape(RULE_PREFIX)}([0-9a-f]{{{RULE_ID_LEN}}})-(Out|In|Allow)$")
_RULE_ID_RE = re.compile(rf"^[0-9a-f]{{{RULE_ID_LEN}}}$")
_SID_RE = re.compile(r"^S-1-15-2(-\d{1,10}){1,15}$")
# Program paths only ever go into double-quoted netsh arguments (never into
# PowerShell), so a double quote / control char is all that must be refused.
_FORBIDDEN_PATH_CHARS = set('"\r\n\t')
OUTBOUND_ACTIONS = ("Allow", "Block", "NotConfigured")


class FirewallError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return (self.stdout.strip() or self.stderr.strip())[:500]


Runner = Callable[[str], CommandResult]


def make_rule_id(exe: str) -> str:
    return hashlib.sha1(normalize_exe(exe).encode("utf-8")).hexdigest()[:RULE_ID_LEN]


def rule_names(rule_id: str) -> tuple[str, str]:
    return f"{RULE_PREFIX}{rule_id}-Out", f"{RULE_PREFIX}{rule_id}-In"


def allow_rule_name(rule_id: str) -> str:
    return f"{RULE_PREFIX}{rule_id}-Allow"


def parse_rule_name(rule_name: str) -> tuple[str, str] | None:
    """'NetGuard-<id>-Out' -> (id, 'Out')."""
    match = _RULE_NAME_RE.match(rule_name.strip())
    return (match.group(1), match.group(2)) if match else None


def parse_rule_id(rule_name: str) -> str | None:
    parsed = parse_rule_name(rule_name)
    return parsed[0] if parsed and parsed[1] in ("Out", "In") else None


def _decode(data: bytes) -> str:
    if not data:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("mbcs" if IS_WINDOWS else "latin-1", errors="replace")


def default_runner(command: str, timeout: float = 30.0) -> CommandResult:
    kwargs = {"creationflags": CREATE_NO_WINDOW} if IS_WINDOWS else {}
    try:
        proc = subprocess.run(command, capture_output=True, timeout=timeout, **kwargs)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FirewallError(f"command failed: {exc}") from exc
    return CommandResult(proc.returncode, _decode(proc.stdout), _decode(proc.stderr))


def powershell_path() -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return ntpath.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def powershell_command(script: str, exe: str | None = None) -> str:
    """Encoded (no quoting issues) PowerShell invocation with UTF-8 output."""
    full = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'Stop'; " + script
    )
    encoded = base64.b64encode(full.encode("utf-16-le")).decode("ascii")
    return f'"{exe or powershell_path()}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}'


def ps_quote(text: str) -> str:
    """PowerShell single-quoted literal."""
    if any(ch in text for ch in "\r\n\0"):
        raise FirewallError(f"invalid value: {text!r}")
    return "'" + text.replace("'", "''") + "'"


def validate_program_path(exe: str) -> str:
    """Only plain absolute Windows paths: nothing that could break out of the
    quoted netsh / PowerShell argument."""
    if not exe or any(ch in _FORBIDDEN_PATH_CHARS for ch in exe):
        raise FirewallError(f"invalid program path: {exe!r}")
    if not ntpath.isabs(exe):
        raise FirewallError(f"program path must be absolute: {exe!r}")
    return ntpath.normpath(exe)


def validate_package_sid(sid: str) -> str:
    if not _SID_RE.match(sid or ""):
        raise FirewallError(f"invalid package SID: {sid!r}")
    return sid


def _validate_rule_id(rule_id: str) -> str:
    if not _RULE_ID_RE.match(rule_id or ""):
        raise FirewallError(f"invalid rule id: {rule_id!r}")
    return rule_id


class FirewallBackend(ABC):
    name: str = "firewall"
    simulated: bool = False

    # ---- per-program block rules -----------------------------------------
    @abstractmethod
    def add_block(self, rule_id: str, exe: str, package_sid: str = "") -> None: ...

    @abstractmethod
    def remove_block(self, rule_id: str) -> None: ...

    @abstractmethod
    def list_rule_names(self) -> set[str]: ...

    def list_rule_ids(self) -> set[str]:
        return {rid for rid in map(parse_rule_id, self.list_rule_names()) if rid}

    def list_allow_ids(self) -> set[str]:
        out = set()
        for name in self.list_rule_names():
            parsed = parse_rule_name(name)
            if parsed and parsed[1] == "Allow":
                out.add(parsed[0])
        return out

    # ---- kill switch ----------------------------------------------------
    @abstractmethod
    def add_allow(self, rule_id: str, exe: str) -> None: ...

    @abstractmethod
    def remove_allow(self, rule_id: str) -> None: ...

    @abstractmethod
    def get_outbound_policy(self) -> dict[str, str]: ...

    @abstractmethod
    def set_outbound_policy(self, policy: dict[str, str]) -> None: ...

    def firewall_status(self) -> dict[str, bool] | None:
        """Profile name -> enabled. None when unknown."""
        return None


def _validate_policy(policy: dict[str, str]) -> dict[str, str]:
    for profile, action in policy.items():
        if profile not in ("Domain", "Private", "Public") or action not in OUTBOUND_ACTIONS:
            raise FirewallError(f"invalid firewall policy {profile}={action}")
    return policy


class WindowsFirewall(FirewallBackend):
    name = "Windows Defender Firewall"

    def __init__(self, runner: Runner = default_runner, system_root: str | None = None) -> None:
        root = system_root or os.environ.get("SystemRoot", r"C:\Windows")
        # Absolute paths: never resolve these tools through PATH.
        self._netsh = ntpath.join(root, "System32", "netsh.exe")
        self._ps_exe = ntpath.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        self._run = runner

    # ---- command builders (pure, unit-tested) -----------------------------
    def build_add_command(self, rule_name: str, direction: str, exe: str, action: str = "block") -> str:
        if direction not in ("in", "out") or action not in ("block", "allow"):
            raise ValueError((direction, action))
        return (
            f'"{self._netsh}" advfirewall firewall add rule name="{rule_name}" '
            f"dir={direction} action={action} enable=yes profile=any "
            f'program="{exe}" description="Created by NetGuard"'
        )

    def build_delete_command(self, rule_name: str) -> str:
        return f'"{self._netsh}" advfirewall firewall delete rule name="{rule_name}"'

    def build_show_command(self, rule_name: str) -> str:
        return f'"{self._netsh}" advfirewall firewall show rule name="{rule_name}"'

    def build_powershell_command(self, script: str) -> str:
        return powershell_command(script, self._ps_exe)

    def build_package_rules_script(self, rule_id: str, package_sid: str) -> str:
        out_name, in_name = rule_names(rule_id)
        return (
            f"New-NetFirewallRule -DisplayName '{out_name}' -Direction Outbound -Action Block "
            f"-Package '{package_sid}' -Profile Any -Description 'Created by NetGuard' | Out-Null; "
            f"New-NetFirewallRule -DisplayName '{in_name}' -Direction Inbound -Action Block "
            f"-Package '{package_sid}' -Profile Any -Description 'Created by NetGuard' | Out-Null"
        )

    # ---- helpers ------------------------------------------------------------
    def _rule_exists(self, rule_name: str) -> bool:
        # netsh exits 0 when at least one rule matches, 1 otherwise; this is
        # locale independent, unlike its (translated) text output.
        return self._run(self.build_show_command(rule_name)).returncode == 0

    def _delete_verified(self, rule_name: str) -> None:
        self._run(self.build_delete_command(rule_name))  # non-zero if already gone
        if self._rule_exists(rule_name):
            raise FirewallError(f"could not delete rule {rule_name}")

    def _powershell(self, script: str) -> list[str]:
        result = self._run(self.build_powershell_command(script))
        if result.returncode != 0:
            raise FirewallError(f"PowerShell failed: {result.output}")
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    # ---- block rules -------------------------------------------------------
    def add_block(self, rule_id: str, exe: str, package_sid: str = "") -> None:
        _validate_rule_id(rule_id)
        if package_sid:  # Microsoft Store / AppContainer app
            validate_package_sid(package_sid)
            try:
                self._powershell(self.build_package_rules_script(rule_id, package_sid))
            except FirewallError:
                for rule_name in rule_names(rule_id):
                    self._run(self.build_delete_command(rule_name))
                raise
            log.info("Blocked package %s (rule %s)", package_sid, rule_id)
            return

        exe = validate_program_path(exe)
        created: list[str] = []
        try:
            for rule_name, direction in zip(rule_names(rule_id), ("out", "in")):
                result = self._run(self.build_add_command(rule_name, direction, exe))
                if result.returncode != 0:
                    raise FirewallError(f"could not create rule {rule_name}: {result.output}")
                created.append(rule_name)
        except FirewallError:
            for rule_name in created:  # roll back half-applied block
                self._run(self.build_delete_command(rule_name))
            raise
        log.info("Blocked %s (rule %s)", exe, rule_id)

    def remove_block(self, rule_id: str) -> None:
        _validate_rule_id(rule_id)
        for rule_name in rule_names(rule_id):
            self._delete_verified(rule_name)
        log.info("Unblocked rule %s", rule_id)

    def list_rule_names(self) -> set[str]:
        return set(
            self._powershell(
                f"Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' -ErrorAction SilentlyContinue "
                "| ForEach-Object { $_.DisplayName }"
            )
        )

    # ---- kill switch -------------------------------------------------------
    def add_allow(self, rule_id: str, exe: str) -> None:
        _validate_rule_id(rule_id)
        exe = validate_program_path(exe)
        name = allow_rule_name(rule_id)
        result = self._run(self.build_add_command(name, "out", exe, action="allow"))
        if result.returncode != 0:
            raise FirewallError(f"could not create rule {name}: {result.output}")

    def remove_allow(self, rule_id: str) -> None:
        _validate_rule_id(rule_id)
        self._delete_verified(allow_rule_name(rule_id))

    def get_outbound_policy(self) -> dict[str, str]:
        lines = self._powershell(
            "Get-NetFirewallProfile | ForEach-Object { '{0}={1}' -f $_.Name, $_.DefaultOutboundAction }"
        )
        policy = {}
        for line in lines:
            name, _, value = line.partition("=")
            if name in ("Domain", "Private", "Public") and value in OUTBOUND_ACTIONS:
                policy[name] = value
        if not policy:
            raise FirewallError("could not read firewall profiles")
        return policy

    def build_set_policy_script(self, policy: dict[str, str]) -> str:
        _validate_policy(policy)
        return "; ".join(
            f"Set-NetFirewallProfile -Name {profile} -DefaultOutboundAction {action}"
            for profile, action in sorted(policy.items())
        )

    def set_outbound_policy(self, policy: dict[str, str]) -> None:
        self._powershell(self.build_set_policy_script(policy))

    def firewall_status(self) -> dict[str, bool] | None:
        try:
            lines = self._powershell(
                "Get-NetFirewallProfile | ForEach-Object { '{0}={1}' -f $_.Name, $_.Enabled }"
            )
        except FirewallError as exc:
            log.warning("Could not read firewall profile state: %s", exc)
            return None
        status: dict[str, bool] = {}
        for line in lines:
            name, _, value = line.partition("=")
            if name:
                status[name] = value.strip().lower() != "false"
        return status or None


class DryRunFirewall(FirewallBackend):
    """In-memory backend for non-Windows development and tests."""

    name = "Dry-run (simulation)"
    simulated = True

    def __init__(self) -> None:
        self._rules: dict[str, str] = {}
        self._policy = {"Domain": "NotConfigured", "Private": "NotConfigured", "Public": "NotConfigured"}
        self._lock = threading.Lock()

    @property
    def policy(self) -> dict[str, str]:
        return dict(self._policy)

    def add_block(self, rule_id: str, exe: str, package_sid: str = "") -> None:
        _validate_rule_id(rule_id)
        if package_sid:
            validate_package_sid(package_sid)
        elif not exe:
            raise FirewallError("empty program path")
        with self._lock:
            for name in rule_names(rule_id):
                self._rules[name] = package_sid or exe

    def remove_block(self, rule_id: str) -> None:
        _validate_rule_id(rule_id)
        with self._lock:
            for name in rule_names(rule_id):
                self._rules.pop(name, None)

    def list_rule_names(self) -> set[str]:
        with self._lock:
            return set(self._rules)

    def add_allow(self, rule_id: str, exe: str) -> None:
        _validate_rule_id(rule_id)
        with self._lock:
            self._rules[allow_rule_name(rule_id)] = exe

    def remove_allow(self, rule_id: str) -> None:
        with self._lock:
            self._rules.pop(allow_rule_name(rule_id), None)

    def get_outbound_policy(self) -> dict[str, str]:
        return dict(self._policy)

    def set_outbound_policy(self, policy: dict[str, str]) -> None:
        self._policy.update(_validate_policy(dict(policy)))


def create_backend() -> FirewallBackend:
    return WindowsFirewall() if IS_WINDOWS else DryRunFirewall()
