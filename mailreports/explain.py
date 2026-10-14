# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Plain-language descriptions of report records and TLS results."""
from __future__ import annotations

import json
from dataclasses import dataclass

from .i18n import _, current, ngettext
from .sources import Verdict, _loads


@dataclass
class Explanation:
    level: str      # ok, warn, bad
    title: str
    text: str

    def __post_init__(self):
        self.text = self.text[:1].upper() + self.text[1:]


def country_name(info) -> str:
    if not info or not info["country"]:
        return ""
    try:
        names = json.loads(info["country_names"] or "{}")
    except (TypeError, ValueError):
        names = {}
    return names.get(current()) or names.get("en") or info["country"]


def origin(info) -> str:
    """'Germany, AS3320 Deutsche Telekom' or ''."""
    parts = []
    name = country_name(info)
    if name:
        parts.append(name)
    if info and info["asn"]:
        parts.append(f"AS{info['asn']} {info['as_org'] or ''}".strip())
    return ", ".join(parts)


def kind_label(kind: str) -> str:
    return {
        "own": _("eigener Server"),
        "relay": _("beauftragter Dienst"),
        "forwarder": _("Weiterleitung"),
        "unknown": _("unbekannt"),
    }.get(kind, kind)


def source_label(verdict: Verdict, ip: str, info) -> str:
    if verdict.source:
        return verdict.source.name
    host = info["ptr"] if info and info["ptr"] else ip
    where = origin(info)
    if verdict.kind == "forwarder":
        return _("Weiterleitung über {host}", host=host)
    if where:
        return _("unbekannter Absender {host} ({where})", host=host, where=where)
    return _("unbekannter Absender {host}", host=host)


def disposition_text(disposition: str) -> str:
    return {
        "none": _("trotzdem zugestellt"),
        "quarantine": _("in Quarantäne bzw. in den Spam-Ordner verschoben"),
        "reject": _("komplett abgewiesen"),
    }.get(disposition, disposition or "?")


def disposition_label(disposition: str) -> str:
    return {
        "none": _("zugestellt"),
        "quarantine": _("Quarantäne"),
        "reject": _("abgewiesen"),
    }.get(disposition, disposition or "?")


def _aligned_dkim(dkim: list[dict], domain: str, strict: bool) -> dict | None:
    for sig in dkim:
        if sig.get("result") != "pass":
            continue
        d = sig.get("domain", "")
        if d == domain or (not strict and (d.endswith("." + domain) or domain.endswith("." + d))):
            return sig
    return None


def explain_record(record, verdict: Verdict, info, policy) -> Explanation:
    """One record of a DMARC report in plain words. policy: row of dmarc_reports."""
    n = record["count"]
    domain = record["header_from"] or policy["domain"]
    who = source_label(verdict, record["source_ip"], info)
    dkim = _loads(record["dkim"])
    spf = _loads(record["spf"])
    mails = ngettext("Diese Mail", "Diese {n} Mails", n)
    good_sig = _aligned_dkim(dkim, domain, policy["adkim"] == "s")
    passing_foreign = [s for s in dkim if s.get("result") == "pass" and s is not good_sig]

    if record["dmarc_pass"]:
        parts = []
        if record["dkim_eval"] == "pass":
            sel = (good_sig or {}).get("selector") or "?"
            parts.append(_("korrekt mit {domain} signiert (DKIM-Selektor {sel})", domain=domain, sel=sel))
        if record["spf_eval"] == "pass":
            parts.append(_("die IP ist per SPF für {domain} erlaubt", domain=domain))
        text = _("{mails} kamen von {who} und waren {details}. DMARC bestanden.",
                 mails=mails, who=who, details=_(" und ").join(parts))
        if record["spf_eval"] != "pass" and verdict.kind == "forwarder":
            text += " " + _("SPF passte nicht, weil die Mails weitergeleitet wurden – "
                            "die DKIM-Signatur hat das überstanden, das ist in Ordnung.")
        elif record["spf_eval"] != "pass" and verdict.kind in ("own", "relay"):
            text += " " + _("SPF passte allerdings nicht – prüfe, ob diese IP im SPF-Eintrag steht.")
        elif record["dkim_eval"] != "pass" and verdict.kind in ("own", "relay"):
            text += " " + _("DKIM fehlte oder passte nicht – nur SPF hat DMARC gerettet. "
                            "Bei Weiterleitungen würden diese Mails durchfallen.")
        level = "ok" if record["dkim_eval"] == "pass" else "warn"
        return Explanation(level, _("DMARC bestanden"), text)

    # failed
    reasons = []
    if not dkim or all(s.get("result") != "pass" for s in dkim):
        reasons.append(_("keine gültige DKIM-Signatur"))
    elif passing_foreign:
        doms = ", ".join(sorted({s.get("domain", "?") for s in passing_foreign}))
        reasons.append(_("nur mit fremder Domain signiert ({doms})", doms=doms))
    spf_res = ", ".join(sorted({s.get("result", "?") for s in spf})) or "none"
    if record["spf_eval"] != "pass":
        if any(s.get("result") == "pass" for s in spf):
            env = record["envelope_from"] or ", ".join(s.get("domain", "") for s in spf)
            reasons.append(_("SPF nur für eine andere Absender-Domain bestanden ({env})", env=env))
        else:
            reasons.append(_("SPF-Ergebnis: {res}", res=spf_res))
    outcome = disposition_text(record["disposition"])
    why = "; ".join(reasons)
    if verdict.kind == "unknown":
        text = _("{who} hat versucht, als {domain} zu senden ({count}): {why}. Der Empfänger hat sie {outcome}.",
                 who=who, domain=domain, count=ngettext("{n} Mail", "{n} Mails", n), why=why, outcome=outcome)
        level = "bad" if record["disposition"] == "none" else "warn"
        return Explanation(level, _("Fremder Absender abgewehrt") if record["disposition"] != "none"
                           else _("Fremder Absender zugestellt"), text)
    if verdict.kind == "forwarder":
        text = _("{mails} wurden über {who} weitergeleitet und haben dabei die Prüfung verloren: {why}. "
                 "Der Empfänger hat sie {outcome}.", mails=mails, who=who, why=why, outcome=outcome)
        return Explanation("warn", _("Weiterleitung durchgefallen"), text)
    text = _("{mails} kamen von {who} – eigentlich ein bekannter Absender –, aber DMARC schlug fehl: {why}. "
             "Der Empfänger hat sie {outcome}. Hier stimmt vermutlich eine Einstellung nicht.",
             mails=mails, who=who, why=why, outcome=outcome)
    return Explanation("bad", _("Bekannter Absender durchgefallen"), text)


# ---------------------------------------------------------------- TLS

def tls_result(result_type: str) -> tuple[str, str]:
    """Short title and explanation for an RFC 8460 result type."""
    table = {
        "starttls-not-supported": (
            _("Kein STARTTLS"),
            _("Der empfangende Server hat keine Verschlüsselung angeboten.")),
        "certificate-host-mismatch": (
            _("Zertifikat passt nicht zum Namen"),
            _("Das Zertifikat des Mailservers gilt für einen anderen Hostnamen als den MX-Eintrag.")),
        "certificate-expired": (
            _("Zertifikat abgelaufen"),
            _("Das Zertifikat des Mailservers ist abgelaufen – sofort erneuern.")),
        "certificate-not-trusted": (
            _("Zertifikat nicht vertrauenswürdig"),
            _("Das Zertifikat stammt nicht von einer anerkannten Stelle oder die Zwischenzertifikate fehlen.")),
        "validation-failure": (
            _("Prüfung fehlgeschlagen"),
            _("Die Verbindung konnte nicht sicher geprüft werden (allgemeiner Fehler).")),
        "tlsa-invalid": (
            _("TLSA-Eintrag ungültig"),
            _("Der DANE/TLSA-Eintrag im DNS passt nicht zum Zertifikat – oft nach einem Zertifikatswechsel.")),
        "dnssec-invalid": (
            _("DNSSEC ungültig"),
            _("Die DNSSEC-Signaturen der Domain ließen sich nicht prüfen.")),
        "dane-required": (
            _("DANE verlangt, aber nicht nutzbar"),
            _("Der Absender verlangt DANE, konnte es aber nicht anwenden.")),
        "sts-policy-fetch-error": (
            _("MTA-STS-Richtlinie nicht abrufbar"),
            _("Die Datei unter https://mta-sts.<domain>/.well-known/mta-sts.txt war nicht erreichbar.")),
        "sts-policy-invalid": (
            _("MTA-STS-Richtlinie ungültig"),
            _("Die MTA-STS-Datei hat einen Formfehler.")),
        "sts-webpki-invalid": (
            _("MTA-STS-Zertifikat ungültig"),
            _("Das HTTPS-Zertifikat von mta-sts.<domain> ist ungültig.")),
    }
    return table.get(result_type, (result_type, _("Unbekannter Fehlertyp laut Bericht.")))


def tls_policy_label(policy_type: str) -> str:
    return {
        "sts": "MTA-STS",
        "tlsa": "DANE (TLSA)",
        "no-policy-found": _("keine Richtlinie"),
    }.get(policy_type, policy_type or "?")
