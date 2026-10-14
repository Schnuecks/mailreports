# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Reverse DNS and GeoIP data for sending IPs (cached in ip_info, refreshed monthly)."""
from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

from .config import Settings
from .db import Database

log = logging.getLogger(__name__)

DNS_TIMEOUT = 4


class GeoIP:
    def __init__(self, settings: Settings):
        self.city = self.country = self.asn = None
        try:
            import maxminddb
        except ImportError:  # pragma: no cover - dependency is in requirements.txt
            return
        for attr, path in (("city", settings.geoip_city_db), ("country", settings.geoip_country_db),
                           ("asn", settings.geoip_asn_db)):
            if not path:
                continue
            try:
                setattr(self, attr, maxminddb.open_database(path))
                log.info("GeoIP database %s loaded", path)
            except (OSError, ValueError) as exc:
                log.warning("GeoIP database %s not usable: %s", path, exc)

    @property
    def available(self) -> bool:
        return bool(self.city or self.country)

    def lookup(self, ip: str) -> dict:
        out: dict = {}
        try:
            rec = (self.city or self.country).get(ip) if (self.city or self.country) else None
        except ValueError:
            rec = None
        if rec:
            country = rec.get("country") or rec.get("registered_country") or {}
            out["country"] = country.get("iso_code")
            names = country.get("names") or {}
            out["country_names"] = {k: v for k, v in names.items() if k in ("de", "en")}
            city = (rec.get("city") or {}).get("names", {}).get("en")
            if city:
                out["city"] = city
        if self.asn:
            try:
                asn = self.asn.get(ip)
            except ValueError:
                asn = None
            if asn:
                out["asn"] = asn.get("autonomous_system_number")
                out["as_org"] = asn.get("autonomous_system_organization")
        return out


def reverse_dns(ip: str) -> tuple[str | None, bool]:
    """PTR name and whether it resolves back to the same IP (forward-confirmed)."""
    try:
        name = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
    except (OSError, UnicodeError):
        return None, False
    try:
        addrs = {a[4][0] for a in socket.getaddrinfo(name, None)}
    except (OSError, UnicodeError):
        return name, False
    return name, ip in addrs


def enrich(db: Database, settings: Settings, geo: GeoIP, ips: list[str] | None = None) -> int:
    """Look up all IPs without (current) data. Returns the number of updated IPs."""
    todo = ips if ips is not None else db.ips_without_info()
    if not todo:
        return 0
    ptrs: dict[str, tuple[str | None, bool]] = {}
    if settings.dns_lookups:
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {ip: pool.submit(reverse_dns, ip) for ip in todo}
            for ip, fut in futures.items():
                try:
                    ptrs[ip] = fut.result(timeout=DNS_TIMEOUT)
                except FutureTimeout:
                    ptrs[ip] = (None, False)
    for ip in todo:
        info = geo.lookup(ip)
        ptr, confirmed = ptrs.get(ip, (None, False))
        info["ptr"] = ptr
        info["ptr_confirmed"] = int(confirmed)
        db.save_ip_info(ip, info)
    log.info("IP data updated for %d addresses", len(todo))
    return len(todo)
