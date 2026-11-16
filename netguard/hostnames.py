"""Turn remote IPs into readable destinations.

* Host names: first from the Windows DNS client cache (the name the program
  actually looked up, e.g. "www.youtube.com"), then reverse DNS (PTR).
* Countries (opt-in): api.country.is over HTTPS, batched, cached on disk.
All lookups run in a small thread pool; `lookup()` never blocks — results show
up on a following scan.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from .config import IS_WINDOWS
from .firewall import FirewallError, default_runner, powershell_command

log = logging.getLogger(__name__)

DNS_CACHE_REFRESH_S = 20.0
COUNTRY_API = "https://api.country.is/"
COUNTRY_BATCH = 100
NEGATIVE_TTL_S = 600.0


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%", 1)[0]).is_global
    except ValueError:
        return False


def read_windows_dns_cache() -> dict[str, str]:
    """ip -> queried name, from Get-DnsClientCache (A and AAAA records)."""
    script = ("Get-DnsClientCache -ErrorAction SilentlyContinue | "
              "Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | "
              "ForEach-Object { '{0}|{1}' -f $_.Data, $_.Entry }")
    try:
        result = default_runner(powershell_command(script), timeout=15)
    except FirewallError as exc:
        log.debug("DNS cache read failed: %s", exc)
        return {}
    mapping: dict[str, str] = {}
    for line in result.stdout.splitlines():
        ip, _, name = line.strip().partition("|")
        if ip and name:
            mapping[ip.strip()] = name.strip().rstrip(".").lower()
    return mapping


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip.split("%", 1)[0])[0].rstrip(".").lower()
    except (OSError, UnicodeError):
        return ""


def fetch_countries(ips: list[str], timeout: float = 8.0) -> dict[str, str]:
    """Batch lookup at api.country.is -> {ip: 'US'}."""
    body = json.dumps(ips).encode()
    request = urllib.request.Request(
        COUNTRY_API, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "NetGuard"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (fixed https URL)
        data = json.loads(response.read().decode("utf-8"))
    items = data if isinstance(data, list) else [data]
    out = {}
    for item in items:
        if isinstance(item, dict) and item.get("ip") and item.get("country"):
            out[str(item["ip"])] = str(item["country"]).upper()[:2]
    return out


class HostResolver:
    def __init__(
        self,
        cache_path: Path | None = None,
        dns_cache_reader: Callable[[], dict[str, str]] | None = None,
        ptr_lookup: Callable[[str], str] = reverse_dns,
        country_fetcher: Callable[[list[str]], dict[str, str]] = fetch_countries,
        clock: Callable[[], float] = time.monotonic,
        executor: ThreadPoolExecutor | None = None,
    ) -> None:
        self._dns_reader = dns_cache_reader if dns_cache_reader is not None else (
            read_windows_dns_cache if IS_WINDOWS else (lambda: {}))
        self._ptr = ptr_lookup
        self._fetch_countries = country_fetcher
        self._clock = clock
        self._pool = executor or ThreadPoolExecutor(max_workers=4, thread_name_prefix="resolver")
        self._lock = threading.Lock()
        self._hosts: dict[str, str] = {}
        self._dns_cache: dict[str, str] = {}
        self._dns_refreshed = -1e9
        self._dns_pending = False
        self._ptr_pending: set[str] = set()
        self._ptr_failed: dict[str, float] = {}
        self._countries: dict[str, str] = {}
        self._country_pending: set[str] = set()
        self._country_failed: dict[str, float] = {}
        self._country_batch_running = False
        self._cache_path = cache_path
        self.hostnames_enabled = True
        self.countries_enabled = False
        self._load_country_cache()

    # ---- public -------------------------------------------------------------
    def lookup(self, ip: str) -> tuple[str, str]:
        """(host, country) from cache; schedules missing lookups."""
        host = country = ""
        if self.hostnames_enabled:
            host = self._host_for(ip)
        if self.countries_enabled and is_public_ip(ip):
            country = self._country_for(ip)
        return host, country

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    # ---- hostnames ------------------------------------------------------------
    def _host_for(self, ip: str) -> str:
        now = self._clock()
        with self._lock:
            refresh = now - self._dns_refreshed > DNS_CACHE_REFRESH_S and not self._dns_pending
            if refresh:
                self._dns_pending = True
        if refresh:  # never submit while holding the lock
            self._pool.submit(self._refresh_dns_cache)
        with self._lock:
            name = self._dns_cache.get(ip) or self._hosts.get(ip)
            if name:
                return name
            failed_at = self._ptr_failed.get(ip)
            if ip in self._ptr_pending or (failed_at is not None and now - failed_at < NEGATIVE_TTL_S):
                return ""
            self._ptr_pending.add(ip)
        self._pool.submit(self._resolve_ptr, ip)
        return ""

    def _refresh_dns_cache(self) -> None:
        try:
            mapping = self._dns_reader()
        except Exception:  # never kill the pool thread
            log.exception("DNS cache refresh failed")
            mapping = {}
        with self._lock:
            # keep older names too: entries expire from the OS cache quickly
            self._dns_cache.update(mapping)
            self._dns_refreshed = self._clock()
            self._dns_pending = False

    def _resolve_ptr(self, ip: str) -> None:
        name = self._ptr(ip)
        with self._lock:
            self._ptr_pending.discard(ip)
            if name:
                self._hosts[ip] = name
            else:
                self._ptr_failed[ip] = self._clock()

    # ---- countries -------------------------------------------------------------
    def _country_for(self, ip: str) -> str:
        now = self._clock()
        with self._lock:
            code = self._countries.get(ip)
            if code:
                return code
            failed_at = self._country_failed.get(ip)
            if failed_at is not None and now - failed_at < NEGATIVE_TTL_S:
                return ""
            self._country_pending.add(ip)
            if self._country_batch_running:
                return ""
            self._country_batch_running = True
        self._pool.submit(self._country_batch)
        return ""

    def _country_batch(self) -> None:
        try:
            while True:
                with self._lock:
                    batch = sorted(self._country_pending)[:COUNTRY_BATCH]
                    if not batch:
                        self._country_batch_running = False
                        return
                    self._country_pending.difference_update(batch)
                try:
                    found = self._fetch_countries(batch)
                except Exception as exc:  # network / HTTP / JSON errors
                    log.info("Country lookup failed: %s", exc)
                    found = {}
                now = self._clock()
                with self._lock:
                    self._countries.update(found)
                    for ip in batch:
                        if ip not in found:
                            self._country_failed[ip] = now
                self._save_country_cache()
                with self._lock:
                    more = bool(self._country_pending)
                if more:
                    time.sleep(0.2)  # stay far below the API's 10 req/s limit
        except Exception:
            log.exception("country batch crashed")
            with self._lock:
                self._country_batch_running = False

    def _load_country_cache(self) -> None:
        if not self._cache_path or not self._cache_path.exists():
            return
        try:
            data = json.loads(self._cache_path.read_text(encoding="utf-8"))
            self._countries = {str(k): str(v) for k, v in data.items()}
        except (OSError, ValueError, AttributeError):
            self._countries = {}

    def _save_country_cache(self) -> None:
        if not self._cache_path:
            return
        with self._lock:
            data = dict(list(self._countries.items())[-20000:])
        tmp = self._cache_path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, self._cache_path)
        except OSError as exc:
            log.debug("country cache save failed: %s", exc)
