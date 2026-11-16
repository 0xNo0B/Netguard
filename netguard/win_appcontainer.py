"""Detect Microsoft Store (AppContainer) processes and read their package SID.

Store apps run in an AppContainer; Windows Firewall filters them by package
SID, so a program-path rule may not apply. We read the SID from the process
token (TokenIsAppContainer / TokenAppContainerSid).
"""
from __future__ import annotations

import ctypes
import logging

from .config import IS_WINDOWS

log = logging.getLogger(__name__)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TOKEN_IS_APP_CONTAINER = 29
TOKEN_APP_CONTAINER_SID = 31

_api = None


def _load_api():
    global _api
    if _api is not None:
        return _api
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _api = (kernel32, advapi32, wintypes)
    return _api


def get_app_container_sid(pid: int) -> str:
    """'S-1-15-2-…' for an AppContainer process, '' otherwise or on any error."""
    if not IS_WINDOWS or not pid:
        return ""
    try:
        kernel32, advapi32, wintypes = _load_api()
    except (OSError, AttributeError):
        return ""
    process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process:
        return ""
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
            return ""
        try:
            is_container = wintypes.DWORD(0)
            size = wintypes.DWORD(0)
            ok = advapi32.GetTokenInformation(token, TOKEN_IS_APP_CONTAINER, ctypes.byref(is_container),
                                              ctypes.sizeof(is_container), ctypes.byref(size))
            if not ok or not is_container.value:
                return ""
            buffer = ctypes.create_string_buffer(512)
            if not advapi32.GetTokenInformation(token, TOKEN_APP_CONTAINER_SID, buffer,
                                                ctypes.sizeof(buffer), ctypes.byref(size)):
                return ""
            # TOKEN_APPCONTAINER_INFORMATION { PSID TokenAppContainer; }
            psid = ctypes.c_void_p.from_buffer(buffer).value
            if not psid:
                return ""
            text = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(psid, ctypes.byref(text)):
                return ""
            try:
                return text.value or ""
            finally:
                kernel32.LocalFree(text)
        finally:
            kernel32.CloseHandle(token)
    except OSError as exc:
        log.debug("AppContainer lookup failed for %s: %s", pid, exc)
        return ""
    finally:
        kernel32.CloseHandle(process)


def is_store_app_path(exe: str) -> bool:
    return "\\windowsapps\\" in exe.lower()
