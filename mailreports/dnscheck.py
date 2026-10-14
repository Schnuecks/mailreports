# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Checks the DNS records of a domain: DMARC, SPF, DKIM, MTA-STS, TLS-RPT, MX and DANE.

Texts are German (translation keys) and are translated when the page is rendered.
"""
from __future__ import annotations

import base64
import ipaddress
import logging
import re
import socket
import ssl
import threading
import time
import urllib.request
from dataclasses import dataclass, field

import dns.exception
import dns.resolver
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from .i18n import N_

log = logging.getLogger(__name__)

TIMEOUT = 4
CACHE_SECONDS = 600
SPF_LOOKUP_LIMIT = 10


@dataclass
class Finding:
    level: str              # ok, info, warn, bad
    text: str               # German key
    args: dict = field(default_factory=dict)


@dataclass
class Section:
    key: str
    title: str
    record: str = ""
    findings: list[Finding] = field(default_factory=list)

    def add(self, level: str, text: str, **args) -> None:
        self.findings.append(Finding(level, text, args))

    @property
    def level(self) -> str:
        order = {"bad": 3, "warn": 2, "info": 1, "ok": 0}
        return max((f.level for f in self.findings), key=lambda x: order[x], default="ok")


class DnsError(Exception):
    pass


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = TIMEOUT
    return r


def txt(name: str) -> list[str]:
    try:
        answer = _resolver().resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        raise DnsError(str(exc)) from exc
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]


def mx(domain: str) -> list[str]:
    try:
        answer = _resolver().resolve(domain, "MX")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        raise DnsError(str(exc)) from exc
    return [str(r.exchange).rstrip(".").lower() for r in sorted(answer, key=lambda r: r.preference)]


def has_record(name: str, rtype: str) -> bool:
    try:
        _resolver().resolve(name, rtype)
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return False


def tags(record: str) -> dict[str, str]:
    out = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


# ---------------------------------------------------------------- DMARC

def check_dmarc(domain: str, mailbox: str) -> Section:
    sec = Section("dmarc", N_("DMARC"))
    records = [t for t in txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if not records:
        sec.add("bad", N_("Kein DMARC-Eintrag unter _dmarc.{domain} gefunden."), domain=domain)
        return sec
    if len(records) > 1:
        sec.add("bad", N_("Mehrere DMARC-Einträge gefunden; empfangende Server ignorieren dann alle."))
    sec.record = records[0]
    t = tags(records[0])
    policy = t.get("p", "").lower()
    if policy == "reject":
        sec.add("ok", N_("Richtlinie p=reject: E-Mails, die DMARC nicht bestehen, werden abgewiesen."))
    elif policy == "quarantine":
        sec.add("ok", N_("Richtlinie p=quarantine: E-Mails, die DMARC nicht bestehen, landen in Quarantäne."))
    elif policy == "none":
        sec.add("warn", N_("Richtlinie p=none: Nur Überwachung, gefälschte E-Mails werden nicht blockiert."))
    else:
        sec.add("bad", N_("Das Pflichtfeld p= fehlt oder ist ungültig."))
    if t.get("pct", "100") != "100":
        sec.add("warn", N_("pct={pct}: Die Richtlinie gilt nur für einen Teil der E-Mails."), pct=t["pct"])
    if "sp" not in t:
        sec.add("info", N_("Kein sp= angegeben: Subdomains übernehmen die Richtlinie p=."))
    rua = [a.strip() for a in t.get("rua", "").split(",") if a.strip()]
    if not rua:
        sec.add("warn", N_("Kein rua= angegeben: Es werden keine Aggregate-Berichte versendet."))
    else:
        addresses = [a[7:].split("!")[0].lower() for a in rua if a.lower().startswith("mailto:")]
        if mailbox and "@" in mailbox and mailbox.lower() not in addresses:
            sec.add("warn", N_("rua= enthält das abgerufene Postfach {mailbox} nicht."), mailbox=mailbox)
        for addr in addresses:
            target = addr.rsplit("@", 1)[-1]
            if target != domain and not target.endswith("." + domain):
                auth = [x for x in txt(f"{domain}._report._dmarc.{target}") if x.lower().startswith("v=dmarc1")]
                if auth:
                    sec.add("ok", N_("Berichte an {target} sind dort freigegeben."), target=target)
                else:
                    sec.add("bad", N_("Berichte an {target} sind dort nicht freigegeben (Eintrag {name} fehlt)."),
                            target=target, name=f"{domain}._report._dmarc.{target}")
    for key, label in (("adkim", "DKIM"), ("aspf", "SPF")):
        if t.get(key, "r").lower() == "s":
            sec.add("info", N_("Strenge Ausrichtung für {what}."), what=label)
    return sec


# ---------------------------------------------------------------- SPF

def _spf_record(domain: str) -> list[str]:
    return [t for t in txt(domain) if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]


def _count_lookups(domain: str, seen: set[str], depth: int = 0) -> int:
    if depth > 10 or domain in seen:
        return 0
    seen.add(domain)
    records = _spf_record(domain)
    if not records:
        return 0
    total = 0
    for term in records[0].split()[1:]:
        term = term.lstrip("+-~?").lower()
        if term.startswith("include:"):
            total += 1 + _count_lookups(term[8:], seen, depth + 1)
        elif term.startswith("redirect="):
            total += 1 + _count_lookups(term[9:], seen, depth + 1)
        elif term in ("a", "mx", "ptr") or term.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
            total += 1
    return total


def check_spf(domain: str) -> Section:
    sec = Section("spf", N_("SPF"))
    records = _spf_record(domain)
    if not records:
        sec.add("bad", N_("Kein SPF-Eintrag gefunden."))
        return sec
    if len(records) > 1:
        sec.add("bad", N_("Mehrere SPF-Einträge gefunden; das ist ungültig und führt zu einem Fehler bei der Prüfung."))
    sec.record = records[0]
    terms = records[0].lower().split()[1:]
    final = next((t for t in terms if t.endswith("all") and t.lstrip("+-~?") == "all"), "")
    if final in ("-all",):
        sec.add("ok", N_("Endet mit -all: Alle anderen Server sind ausdrücklich nicht erlaubt."))
    elif final == "~all":
        sec.add("ok", N_("Endet mit ~all (Softfail); mit DMARC ist das üblich."))
    elif final == "?all":
        sec.add("warn", N_("Endet mit ?all (neutral): Andere Server werden weder erlaubt noch abgelehnt."))
    elif final in ("+all", "all"):
        sec.add("bad", N_("Endet mit +all: Jeder Server der Welt darf im Namen der Domain senden."))
    elif not any(t.startswith("redirect=") for t in terms):
        sec.add("warn", N_("Kein abschließendes all-Element vorhanden."))
    if any(t.lstrip("+-~?").startswith("ptr") for t in terms):
        sec.add("warn", N_("Der Mechanismus ptr ist veraltet und sollte nicht mehr verwendet werden."))
    lookups = _count_lookups(domain, set())
    if lookups > SPF_LOOKUP_LIMIT:
        sec.add("bad", N_("{n} DNS-Abfragen nötig; erlaubt sind höchstens 10, sonst schlägt SPF fehl."), n=lookups)
    else:
        sec.add("ok", N_("{n} von höchstens 10 DNS-Abfragen."), n=lookups)
    return sec


# ---------------------------------------------------------------- DKIM

def _key_bits(p: str) -> tuple[str, int]:
    key = load_der_public_key(base64.b64decode(p))
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.key_size
    return "?", 0


def check_dkim(domain: str, selectors: list[str]) -> Section:
    sec = Section("dkim", N_("DKIM"))
    if not selectors:
        sec.add("info", N_("In den Berichten wurde noch kein DKIM-Selektor dieser Domain gesehen."))
        return sec
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        records = [t for t in txt(name) if "p=" in t]
        if not records:
            sec.add("info", N_("Selektor {sel}: nicht veröffentlicht. Falls der Schlüssel stillgelegt wurde, "
                               "ist das in Ordnung."), sel=sel)
            continue
        t = tags(records[0])
        p = re.sub(r"\s+", "", t.get("p", ""))
        if not p:
            sec.add("info", N_("Selektor {sel}: Schlüssel widerrufen (leeres p=)."), sel=sel)
            continue
        if t.get("k", "rsa").lower() == "ed25519":
            sec.add("ok", N_("Selektor {sel}: Ed25519-Schlüssel."), sel=sel)
            continue
        try:
            algo, bits = _key_bits(p)
        except (ValueError, TypeError):
            sec.add("bad", N_("Selektor {sel}: Der Schlüssel lässt sich nicht lesen."), sel=sel)
            continue
        if algo == "RSA" and bits < 1024:
            sec.add("bad", N_("Selektor {sel}: RSA mit {bits} Bit ist unsicher."), sel=sel, bits=bits)
        elif algo == "RSA" and bits < 2048:
            sec.add("warn", N_("Selektor {sel}: RSA mit {bits} Bit; empfohlen sind mindestens 2048 Bit."),
                    sel=sel, bits=bits)
        else:
            sec.add("ok", N_("Selektor {sel}: {algo} mit {bits} Bit."), sel=sel, algo=algo, bits=bits)
    return sec


# ---------------------------------------------------------------- MTA-STS, TLS-RPT, MX/DANE

def _public_host(host: str) -> bool:
    """True if every address of host is public (no internal targets for the policy fetch)."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        return False
    addrs = {ipaddress.ip_address(i[4][0]) for i in infos}
    return bool(addrs) and all(a.is_global for a in addrs)


def fetch_sts_policy(domain: str) -> str:
    host = f"mta-sts.{domain}"
    if not _public_host(host):
        raise DnsError("not a public address")
    req = urllib.request.Request(f"https://{host}/.well-known/mta-sts.txt", headers={"User-Agent": "mailreports"})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl.create_default_context()) as resp:  # noqa: S310
        return resp.read(65536).decode("utf-8", "replace")


def _mx_matches(host: str, pattern: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")
    return host == pattern


def check_mta_sts(domain: str, mx_hosts: list[str]) -> Section:
    sec = Section("mta_sts", N_("MTA-STS"))
    records = [t for t in txt(f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]
    if not records:
        sec.add("info", N_("Kein MTA-STS: Verschlüsselung bei der Zustellung wird nicht erzwungen."))
        return sec
    sec.record = records[0]
    try:
        policy = fetch_sts_policy(domain)
    except (OSError, DnsError, ssl.SSLError, ValueError) as exc:
        log.info("MTA-STS policy of %s: %s", domain, exc)
        sec.add("bad", N_("Die Richtlinie unter https://mta-sts.{domain}/.well-known/mta-sts.txt ist nicht abrufbar."),
                domain=domain)
        return sec
    fields: dict[str, list[str]] = {}
    for line in policy.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            fields.setdefault(k.strip().lower(), []).append(v.strip())
    mode = (fields.get("mode") or [""])[0].lower()
    if mode == "enforce":
        sec.add("ok", N_("Modus enforce: Zustellung nur über gültiges TLS."))
    elif mode == "testing":
        sec.add("warn", N_("Modus testing: Fehler werden nur gemeldet, nicht erzwungen."))
    else:
        sec.add("warn", N_("Modus {mode}: MTA-STS ist nicht aktiv."), mode=mode or "?")
    patterns = fields.get("mx", [])
    missing = [h for h in mx_hosts if h and not any(_mx_matches(h, p) for p in patterns)]
    if missing:
        sec.add("bad", N_("Diese MX-Server fehlen in der Richtlinie: {hosts}"), hosts=", ".join(missing))
    elif mx_hosts:
        sec.add("ok", N_("Alle MX-Server sind in der Richtlinie enthalten."))
    return sec


def check_tlsrpt(domain: str) -> Section:
    sec = Section("tlsrpt", N_("TLS-RPT"))
    records = [t for t in txt(f"_smtp._tls.{domain}") if t.lower().startswith("v=tlsrptv1")]
    if not records:
        sec.add("warn", N_("Kein TLS-RPT-Eintrag: Es werden keine TLS-Berichte versendet."))
        return sec
    sec.record = records[0]
    rua = tags(records[0]).get("rua", "")
    if rua:
        sec.add("ok", N_("TLS-Berichte gehen an {rua}."), rua=rua)
    else:
        sec.add("bad", N_("Der Eintrag enthält kein rua=."))
    return sec


def check_mx(domain: str, mx_hosts: list[str]) -> Section:
    sec = Section("mx", N_("MX und DANE"))
    if mx_hosts == [""]:
        sec.record = "MX 0 ."
        sec.add("info", N_("Null-MX (RFC 7505): Die Domain empfängt ausdrücklich keine E-Mails."))
        return sec
    if not mx_hosts:
        sec.add("warn", N_("Keine MX-Einträge: Die Domain empfängt keine E-Mails."))
        return sec
    sec.record = ", ".join(mx_hosts)
    for host in mx_hosts:
        if has_record(f"_25._tcp.{host}", "TLSA"):
            sec.add("ok", N_("{host}: TLSA-Eintrag vorhanden (DANE)."), host=host)
        else:
            sec.add("info", N_("{host}: kein TLSA-Eintrag (kein DANE)."), host=host)
    return sec


# ---------------------------------------------------------------- all together

_cache: dict[str, tuple[float, list[Section]]] = {}
_lock = threading.Lock()


def check_domain(domain: str, selectors: list[str], mailbox: str, refresh: bool = False) -> list[Section]:
    with _lock:
        hit = _cache.get(domain)
        if hit and not refresh and hit[0] > time.time():
            return hit[1]
    sections: list[Section] = []
    try:
        mx_hosts = mx(domain)
        sections = [check_dmarc(domain, mailbox), check_spf(domain), check_dkim(domain, selectors),
                    check_mx(domain, mx_hosts), check_mta_sts(domain, mx_hosts), check_tlsrpt(domain)]
    except DnsError as exc:
        err = Section("error", N_("DNS"))
        err.add("bad", N_("Die DNS-Abfrage ist fehlgeschlagen: {error}"), error=str(exc)[:200])
        sections.append(err)
    with _lock:
        _cache[domain] = (time.time() + CACHE_SECONDS, sections)
    return sections
