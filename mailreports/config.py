# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Settings from the environment.

Every secret can also be read from a file: IMAP_PASSWORD_FILE=/run/secrets/imap
takes precedence over IMAP_PASSWORD (works for all variables).
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path


def env(name: str, default: str = "") -> str:
    """Value of NAME, or the content of the file named in NAME_FILE."""
    path = os.environ.get(f"{name}_FILE", "").strip()
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SystemExit(f"{name}_FILE: cannot read {path}: {exc}") from exc
    return os.environ.get(name, default).strip()


def env_int(name: str, default: int) -> int:
    value = env(name)
    try:
        return int(value) if value else default
    except ValueError:
        raise SystemExit(f"{name} must be a whole number, got {value!r}") from None


def env_bool(name: str, default: bool) -> bool:
    value = env(name).lower()
    if not value:
        return default
    return value in ("1", "true", "yes", "on")


def env_list(name: str) -> list[str]:
    return [part.strip() for part in env(name).replace(";", ",").split(",") if part.strip()]


def _networks(values: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets = []
    for value in values:
        try:
            nets.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise SystemExit(f"TRUSTED_PROXIES: {value!r} is not an IP address or network") from None
    return nets


def _first_existing(*paths: Path) -> str:
    for path in paths:
        if path.is_file():
            return str(path)
    return ""


@dataclass
class Settings:
    data_dir: Path = Path("/data")
    # IMAP
    imap_host: str = ""
    imap_port: int = 993
    imap_security: str = "ssl"        # ssl (port 993), starttls (port 143) or none (tests only)
    imap_user: str = ""
    imap_password: str = ""
    imap_folder: str = "INBOX"
    imap_move_to: str = ""            # folder for processed mails; empty = only flag them
    imap_error_folder: str = ""       # folder for mails without a usable report; empty = flag
    imap_readonly: bool = False       # never change the mailbox, remember processed mails in the database
    fetch_interval: int = 900         # seconds between two fetches
    # Enrichment
    dns_lookups: bool = True
    geoip_city_db: str = ""
    geoip_country_db: str = ""
    geoip_asn_db: str = ""
    sources_file: str = ""
    # Notifications
    pushover_token: str = ""
    pushover_user: str = ""
    notify_cooldown_hours: int = 24
    base_url: str = ""
    # Access
    auth_header: str = ""             # e.g. Remote-User: requests without it are refused
    allowed_groups: list[str] = field(default_factory=list)
    trusted_proxies: list = field(default_factory=list)
    # Appearance
    app_title: str = ""
    logo_url: str = ""
    default_language: str = ""
    domains: list[str] = field(default_factory=list)
    source_url: str = "https://github.com/Schnuecks/mailreports"
    timezone: str = "UTC"
    background_tasks: bool = True

    @property
    def db_path(self) -> Path:
        return self.data_dir / "mailreports.sqlite3"

    @property
    def imap_enabled(self) -> bool:
        return bool(self.imap_host and self.imap_user)

    @property
    def pushover_enabled(self) -> bool:
        return bool(self.pushover_token and self.pushover_user)


def load() -> Settings:
    geoip_dir = Path(env("GEOIP_DIR", "/geoip"))
    security = env("IMAP_SECURITY", "ssl").lower()
    if security not in ("ssl", "starttls", "none"):
        raise SystemExit("IMAP_SECURITY must be ssl, starttls or none")
    return Settings(
        data_dir=Path(env("DATA_DIR", "/data")),
        imap_host=env("IMAP_HOST"),
        imap_port=env_int("IMAP_PORT", 143 if security == "starttls" else 993),
        imap_security=security,
        imap_user=env("IMAP_USER"),
        imap_password=env("IMAP_PASSWORD"),
        imap_folder=env("IMAP_FOLDER", "INBOX"),
        imap_move_to=env("IMAP_MOVE_TO"),
        imap_error_folder=env("IMAP_ERROR_FOLDER"),
        imap_readonly=env_bool("IMAP_READONLY", False),
        fetch_interval=max(60, env_int("FETCH_INTERVAL", 900)),
        dns_lookups=env_bool("DNS_LOOKUPS", True),
        geoip_city_db=env("GEOIP_CITY_DB") or _first_existing(geoip_dir / "GeoLite2-City.mmdb"),
        geoip_country_db=env("GEOIP_COUNTRY_DB") or _first_existing(geoip_dir / "GeoLite2-Country.mmdb"),
        geoip_asn_db=env("GEOIP_ASN_DB") or _first_existing(geoip_dir / "GeoLite2-ASN.mmdb"),
        sources_file=env("SOURCES_FILE") or _first_existing(Path("/config/sources.toml")),
        pushover_token=env("PUSHOVER_TOKEN"),
        pushover_user=env("PUSHOVER_USER"),
        notify_cooldown_hours=max(1, env_int("NOTIFY_COOLDOWN_HOURS", 24)),
        base_url=env("BASE_URL").rstrip("/"),
        auth_header=env("AUTH_HEADER"),
        allowed_groups=env_list("ALLOWED_GROUPS"),
        trusted_proxies=_networks(env_list("TRUSTED_PROXIES")),
        app_title=env("APP_TITLE"),
        logo_url=env("LOGO_URL"),
        default_language=env("DEFAULT_LANGUAGE").lower(),
        domains=[d.lower() for d in env_list("DOMAINS")],
        source_url=env("SOURCE_URL", "https://github.com/Schnuecks/mailreports"),
        timezone=env("TZ", "UTC") or "UTC",
        background_tasks=env_bool("BACKGROUND_TASKS", True),
    )
