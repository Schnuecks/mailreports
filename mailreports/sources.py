# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Known senders from sources.toml and the classification of report records.

Example sources.toml:

    [[source]]
    name = "Own mail server"
    kind = "own"
    ips = ["192.0.2.10", "2001:db8::10"]
    ptr = ["mail.example.org"]

    [[source]]
    name = "Newsletter service"
    kind = "relay"
    dkim_selectors = ["nl1", "nl2"]
    note = "Only for newsletters"

kind: own, relay (an authorised third party sending for you), forwarder.
A source matches when any of ips, ptr (exact or ".suffix"), asn, or a passing
DKIM signature with one of dkim_selectors (optionally restricted to dkim_domains) fits.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

KINDS = ("own", "relay", "forwarder", "unknown")


@dataclass
class Source:
    name: str
    kind: str = "relay"
    ips: list = field(default_factory=list)
    ptr: list[str] = field(default_factory=list)
    asn: list[int] = field(default_factory=list)
    dkim_selectors: list[str] = field(default_factory=list)
    dkim_domains: list[str] = field(default_factory=list)
    note: str = ""

    def matches_ip(self, ip: str, ptr: str | None, asn: int | None) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        if addr is not None and any(addr in net for net in self.ips if net.version == addr.version):
            return True
        if ptr:
            p = ptr.lower().rstrip(".")
            for pattern in self.ptr:
                if pattern.startswith(".") and p.endswith(pattern) or p == pattern:
                    return True
        return bool(asn and asn in self.asn)

    def matches_dkim(self, dkim: list[dict]) -> bool:
        if not self.dkim_selectors:
            return False
        for sig in dkim:
            if sig.get("result") != "pass" or sig.get("selector") not in self.dkim_selectors:
                continue
            if not self.dkim_domains or sig.get("domain") in self.dkim_domains:
                return True
        return False


def load_sources(path: str) -> list[Source]:
    if not path:
        return []
    try:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit(f"SOURCES_FILE {path}: {exc}") from exc
    out = []
    for i, item in enumerate(data.get("source", []), 1):
        if not isinstance(item, dict) or not item.get("name"):
            raise SystemExit(f"SOURCES_FILE {path}: entry {i} needs a name")
        kind = str(item.get("kind", "relay")).lower()
        if kind not in KINDS[:-1]:
            raise SystemExit(f"SOURCES_FILE {path}: entry {item['name']!r} has unknown kind {kind!r}")
        try:
            nets = [ipaddress.ip_network(str(v), strict=False) for v in item.get("ips", [])]
        except ValueError as exc:
            raise SystemExit(f"SOURCES_FILE {path}: entry {item['name']!r}: {exc}") from exc
        out.append(Source(
            name=str(item["name"]),
            kind=kind,
            ips=nets,
            ptr=[str(p).lower().rstrip(".") for p in item.get("ptr", [])],
            asn=[int(a) for a in item.get("asn", [])],
            dkim_selectors=[str(s) for s in item.get("dkim_selectors", [])],
            dkim_domains=[str(d).lower() for d in item.get("dkim_domains", [])],
            note=str(item.get("note", "")),
        ))
    log.info("%d known sources loaded from %s", len(out), path)
    return out


@dataclass
class Verdict:
    kind: str                  # own, relay, forwarder, unknown
    source: Source | None
    forwarded_guess: bool = False


def _loads(value) -> list:
    if isinstance(value, list):
        return value
    try:
        return json.loads(value or "[]")
    except (TypeError, ValueError):
        return []


def classify(sources: list[Source], record, info) -> Verdict:
    """Who sent the mails of this record? record: row of dmarc_records, info: row of ip_info or None."""
    ip = record["source_ip"]
    ptr = info["ptr"] if info else None
    asn = info["asn"] if info else None
    dkim = _loads(record["dkim"])
    for src in sources:
        if src.matches_ip(ip, ptr, asn):
            return Verdict(src.kind, src)
    for src in sources:
        if src.matches_dkim(dkim):
            return Verdict(src.kind, src)
    reasons = {r.get("type") for r in _loads(record["reasons"])}
    if reasons & {"forwarded", "trusted_forwarder", "mailing_list"}:
        return Verdict("forwarder", None, forwarded_guess=True)
    # DKIM survived but the sending IP is not allowed by SPF: the typical picture of forwarding
    if record["dkim_eval"] == "pass" and record["spf_eval"] != "pass":
        return Verdict("forwarder", None, forwarded_guess=True)
    return Verdict("unknown", None)


def classify_ip(sources: list[Source], ip: str, info) -> Source | None:
    """Known source by IP data alone (for lists of sending IPs)."""
    ptr = info["ptr"] if info else None
    asn = info["asn"] if info else None
    for src in sources:
        if src.matches_ip(ip, ptr, asn):
            return src
    return None
