# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Recommendation for the DMARC policy of a domain, based on the reports of the last 30 days."""
from __future__ import annotations

from dataclasses import dataclass, field

from .db import Database
from .i18n import N_
from .queries import day_of, since_ts
from .sources import Source, classify
from .web import fmt_pct

DAYS = 30
MIN_DAYS = 14
MIN_MESSAGES = 50
KNOWN_PASS_NEEDED = 98.0


@dataclass
class Advice:
    level: str                       # ok, info, warn
    title: str                       # German key
    text: str
    args: dict = field(default_factory=dict)
    points: list[tuple[str, dict]] = field(default_factory=list)   # (German key, args)
    record: str = ""                 # suggested DMARC record


def policy_advice(db: Database, sources: list[Source], domain: str, current: dict, tz) -> Advice:
    """current: published policy as reported (p, sp, pct, adkim, aspf)."""
    with db.connect() as con:
        rows = con.execute(
            """SELECT r.*, p.date_begin, p.date_end FROM dmarc_records r JOIN dmarc_reports p ON p.id = r.report_id
               WHERE p.domain = ? AND p.date_end >= ?""", (domain, since_ts(DAYS))).fetchall()
        info = {r["ip"]: r for r in con.execute("SELECT * FROM ip_info")} if rows else {}
    days = {day_of((r["date_begin"] + r["date_end"]) // 2, tz) for r in rows}
    total = sum(r["count"] for r in rows)
    policy = (current.get("p") or "").lower()
    if len(days) < MIN_DAYS or total < MIN_MESSAGES:
        return Advice("info", N_("Noch zu wenig Daten"),
                      N_("Für eine Empfehlung werden Berichte aus mindestens {d} Tagen und {m} E-Mails benötigt; "
                         "bisher liegen {have_d} Tage mit {have_m} E-Mails vor."),
                      {"d": MIN_DAYS, "m": MIN_MESSAGES, "have_d": len(days), "have_m": total})

    known = known_pass = spf_only = 0
    unknown_pass: dict[str, int] = {}
    for r in rows:
        verdict = classify(sources, r, info.get(r["source_ip"]))
        if verdict.kind in ("own", "relay"):
            known += r["count"]
            if r["dmarc_pass"]:
                known_pass += r["count"]
                if r["dkim_eval"] != "pass":
                    spf_only += r["count"]
        elif verdict.kind == "unknown" and r["dmarc_pass"]:
            unknown_pass[r["source_ip"]] = unknown_pass.get(r["source_ip"], 0) + r["count"]
    rate = known_pass / known * 100 if known else 0.0

    points: list[tuple[str, dict]] = []
    if not known:
        points.append((N_("Es ist noch keine bekannte Quelle erfasst. Den eigenen Mailserver und beauftragte Dienste "
                          "in sources.toml eintragen."), {}))
    elif rate < KNOWN_PASS_NEEDED:
        points.append((N_("Bekannte Absender bestehen DMARC nur zu {rate}; vor einer strengeren Richtlinie die "
                          "fehlschlagenden Quellen korrigieren."), {"rate": fmt_pct(rate)}))
    if unknown_pass:
        ips = ", ".join(sorted(unknown_pass, key=lambda ip: -unknown_pass[ip])[:5])
        points.append((N_("{n} unbekannte Quellen bestehen DMARC ({ips}). Vermutlich legitime Dienste, die in "
                          "sources.toml fehlen; bitte prüfen."), {"n": len(unknown_pass), "ips": ips}))
    blockers = list(points)
    if spf_only:
        points.append((N_("{n} E-Mails bekannter Absender bestanden nur über SPF, ohne gültige DKIM-Signatur. Bei "
                          "Weiterleitungen würden sie DMARC nicht bestehen."), {"n": spf_only}))
    pct = current.get("pct") or "100"
    base = f"v=DMARC1; p={{p}}; sp={{p}}; adkim={current.get('adkim') or 'r'}; aspf={current.get('aspf') or 'r'}"

    if policy == "reject":
        if pct != "100":
            return Advice("warn", N_("pct auf 100 erhöhen"),
                          N_("p=reject gilt derzeit nur für {pct} % der E-Mails."), {"pct": pct}, points)
        return Advice("ok", N_("Strengste Richtlinie aktiv"),
                      N_("p=reject ist veröffentlicht. Weiter beobachten, ob neue Quellen auftauchen."), {}, points)
    if blockers:
        return Advice("warn", N_("Richtlinie noch nicht verschärfen"),
                      N_("Bevor die Richtlinie verschärft wird, sollten diese Punkte geklärt sein:"), {}, points)
    if policy == "quarantine":
        if pct != "100":
            return Advice("info", N_("pct auf 100 erhöhen"),
                          N_("Alle bekannten Absender bestehen DMARC ({rate}). Zunächst pct=100 setzen, danach ist "
                             "p=reject möglich."), {"rate": fmt_pct(rate)}, points, base.format(p="quarantine"))
        return Advice("ok", N_("p=reject ist möglich"),
                      N_("Alle bekannten Absender bestehen DMARC ({rate}) und es gibt keine unbekannten "
                         "legitimen Quellen. Die Richtlinie kann auf p=reject verschärft werden."),
                      {"rate": fmt_pct(rate)}, points, base.format(p="reject"))
    return Advice("ok", N_("p=quarantine ist möglich"),
                  N_("Alle bekannten Absender bestehen DMARC ({rate}) und es gibt keine unbekannten legitimen "
                     "Quellen. Die Richtlinie kann von p=none auf p=quarantine verschärft werden."),
                  {"rate": fmt_pct(rate)}, points, base.format(p="quarantine"))
