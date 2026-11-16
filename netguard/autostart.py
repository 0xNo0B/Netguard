"""Start with Windows via a Task Scheduler logon task.

A task with "Run with highest privileges" starts the app elevated at logon
without a UAC prompt (a Run-registry entry could not). It is registered with
PowerShell so it can also run on battery and has no 72-hour time limit
(schtasks.exe cannot set those).
"""
from __future__ import annotations

import ntpath
import os
import sys

from .config import APP_NAME, IS_WINDOWS
from .firewall import FirewallError, Runner, default_runner, powershell_command, ps_quote

TASK_NAME = APP_NAME


def launch_target() -> tuple[str, str]:
    """(executable, arguments) the logon task runs; starts hidden in the tray."""
    if getattr(sys, "frozen", False):
        return sys.executable, "--minimized"
    exe = sys.executable
    pythonw = ntpath.join(ntpath.dirname(exe), "pythonw.exe")
    if os.path.exists(pythonw):
        exe = pythonw
    return exe, f'"{os.path.abspath(sys.argv[0])}" --minimized'


def build_register_script(executable: str, arguments: str) -> str:
    user = '"$env:USERDOMAIN\\$env:USERNAME"'
    return (
        f"$a = New-ScheduledTaskAction -Execute {ps_quote(executable)} -Argument {ps_quote(arguments)}; "
        f"$t = New-ScheduledTaskTrigger -AtLogOn -User {user}; $t.Delay = 'PT15S'; "
        f"$p = New-ScheduledTaskPrincipal -UserId {user} -LogonType Interactive -RunLevel Highest; "
        "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
        "-ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew; "
        f"Register-ScheduledTask -TaskName {ps_quote(TASK_NAME)} -Action $a -Trigger $t "
        "-Principal $p -Settings $s -Force | Out-Null"
    )


def is_enabled(runner: Runner = default_runner) -> bool:
    if not IS_WINDOWS:
        return False
    script = (f"if (Get-ScheduledTask -TaskName {ps_quote(TASK_NAME)} -ErrorAction SilentlyContinue) "
              "{ 'yes' } else { 'no' }")
    result = runner(powershell_command(script))
    return result.returncode == 0 and result.stdout.strip().endswith("yes")


def set_enabled(enabled: bool, runner: Runner = default_runner) -> None:
    if not IS_WINDOWS:
        raise FirewallError("start with Windows is only available on Windows")
    if enabled:
        script = build_register_script(*launch_target())
    else:
        script = (f"Unregister-ScheduledTask -TaskName {ps_quote(TASK_NAME)} -Confirm:$false "
                  "-ErrorAction SilentlyContinue")
    result = runner(powershell_command(script))
    if result.returncode != 0:
        raise FirewallError(result.output or "Task Scheduler call failed")
