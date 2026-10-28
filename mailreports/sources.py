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

Admins can add further sources in the app (table known_sources); they are used together
with the ones from the file.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .i18n import N_

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
    id: int | None = None      # set for sources added in the app, None for sources.toml

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


# ---------------------------------------------------------------- sources added in the app

# Networks wider than this would mark large parts of the internet as known and hide spoofing
MIN_PREFIX = {4: 16, 6: 32}
_HOST = re.compile(r"^\.?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
_SELECTOR = re.compile(r"^[A-Za-z0-9._-]{1,63}$")


class Invalid(ValueError):
    """German message (translation key) and the field it belongs to."""

    def __init__(self, message: str, field: str, **params):
        super().__init__(message)
        self.message, self.field, self.params = message, field, params


def _items(value: str) -> list[str]:
    return [v.strip() for v in re.split(r"[,\s]+", value or "") if v.strip()]


def parse_form(form: dict) -> Source:
    """Source from the form of the app. Raises Invalid."""
    name = str(form.get("name", "")).strip()
    if not name or len(name) > 100:
        raise Invalid(N_("Bitte einen Namen mit höchstens 100 Zeichen angeben."), "name")
    kind = str(form.get("kind", "")).strip()
    if kind not in KINDS[:-1]:
        raise Invalid(N_("Ungültige Auswahl."), "kind")
    nets = []
    for value in _items(form.get("ips", "")):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise Invalid(N_("{value} ist keine gültige IP-Adresse und kein gültiges Netz."), "ips",
                          value=value) from None
        if net.prefixlen < MIN_PREFIX[net.version]:
            raise Invalid(N_("Das Netz {value} ist zu groß; erlaubt sind höchstens /{v4} (IPv4) und /{v6} (IPv6)."),
                          "ips", value=value, v4=MIN_PREFIX[4], v6=MIN_PREFIX[6])
        nets.append(net)
    ptr = [p.lower().rstrip(".") for p in _items(form.get("ptr", ""))]
    for value in ptr:
        if not _HOST.match(value) or value.count(".") < 1 + value.startswith("."):
            raise Invalid(N_("{value} ist kein gültiger Rechnername."), "ptr", value=value)
    asn = []
    for value in _items(form.get("asn", "")):
        number = value.upper().removeprefix("AS")
        if not number.isdigit() or not 0 < int(number) < 2 ** 32:
            raise Invalid(N_("{value} ist keine gültige AS-Nummer."), "asn", value=value)
        asn.append(int(number))
    selectors = _items(form.get("dkim_selectors", ""))
    for value in selectors:
        if not _SELECTOR.match(value):
            raise Invalid(N_("{value} ist kein gültiger DKIM-Selektor."), "dkim_selectors", value=value)
    domains = [d.lower().rstrip(".") for d in _items(form.get("dkim_domains", ""))]
    for value in domains:
        if not _HOST.match(value) or value.startswith(".") or "." not in value:
            raise Invalid(N_("{value} ist keine gültige Domain."), "dkim_domains", value=value)
    if not (nets or ptr or asn or selectors):
        raise Invalid(N_("Bitte mindestens ein Merkmal angeben: IP-Adresse, Rechnername, AS-Nummer oder "
                         "DKIM-Selektor."), "ips")
    note = str(form.get("note", "")).strip()[:300]
    return Source(name=name, kind=kind, ips=nets, ptr=ptr, asn=asn, dkim_selectors=selectors,
                  dkim_domains=domains, note=note)


def _from_row(row) -> Source:
    return Source(name=row["name"], kind=row["kind"],
                  ips=[ipaddress.ip_network(v, strict=False) for v in json.loads(row["ips"])],
                  ptr=json.loads(row["ptr"]), asn=json.loads(row["asn"]),
                  dkim_selectors=json.loads(row["dkim_selectors"]), dkim_domains=json.loads(row["dkim_domains"]),
                  note=row["note"], id=row["id"])


def stored_sources(con) -> list[Source]:
    return [_from_row(r) for r in con.execute("SELECT * FROM known_sources ORDER BY name COLLATE NOCASE, id")]


def stored_source(con, source_id: int) -> Source | None:
    row = con.execute("SELECT * FROM known_sources WHERE id = ?", (source_id,)).fetchone()
    return _from_row(row) if row else None


def save_source(con, src: Source, user: str = "") -> int:
    values = (src.name, src.kind, json.dumps([str(n) for n in src.ips]), json.dumps(src.ptr), json.dumps(src.asn),
              json.dumps(src.dkim_selectors), json.dumps(src.dkim_domains), src.note)
    now = int(time.time())
    if src.id:
        con.execute("""UPDATE known_sources SET name=?, kind=?, ips=?, ptr=?, asn=?, dkim_selectors=?,
                       dkim_domains=?, note=?, updated_at=? WHERE id=?""", (*values, now, src.id))
        return src.id
    return con.execute("""INSERT INTO known_sources (name, kind, ips, ptr, asn, dkim_selectors, dkim_domains,
                          note, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                       (*values, user, now, now)).lastrowid


def delete_source(con, source_id: int) -> None:
    con.execute("DELETE FROM known_sources WHERE id = ?", (source_id,))


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
