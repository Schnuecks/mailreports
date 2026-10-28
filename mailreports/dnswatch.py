# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Daily DNS check of the domains: changed records and new problems are stored and reported.

For each domain the last result is kept in the meta table (dns_snapshot:<domain>). The
first check only records the current state; later checks compare against it. A check
that fails because DNS is not reachable changes nothing.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass

from . import dnscheck, i18n, notify, queries
from .config import Settings
from .db import Database
from .i18n import _

log = logging.getLogger(__name__)

PROBLEM_LEVELS = ("warn", "bad")


@dataclass
class Change:
    domain: str
    section: str          # key of the dnscheck section, e.g. spf
    kind: str             # record, problem, resolved
    old: str = ""
    new: str = ""


def _problem_key(f: dnscheck.Finding) -> str:
    # Numbers (e.g. the count of SPF lookups) may change without the problem being a new one
    names = {k: v for k, v in f.args.items() if isinstance(v, str)}
    return f.text + "|" + json.dumps(names, sort_keys=True)


def snapshot(sections: list[dnscheck.Section]) -> dict:
    out = {}
    for sec in sections:
        problems = {_problem_key(f): {"level": f.level, "text": f.text, "args": f.args}
                    for f in sec.findings if f.level in PROBLEM_LEVELS}
        out[sec.key] = {"record": sec.record, "problems": problems}
    return out


def compare(domain: str, old: dict, new: dict) -> list[Change]:
    changes = []
    for key in new.keys() | old.keys():
        before, after = old.get(key), new.get(key)
        if before is None or after is None:
            continue    # check added or removed in a new version of mailreports
        if before["record"] != after["record"]:
            changes.append(Change(domain, key, "record", before["record"], after["record"]))
        for pkey, problem in after["problems"].items():
            if pkey not in before["problems"]:
                changes.append(Change(domain, key, "problem", new=json.dumps(problem, ensure_ascii=False)))
        for pkey, problem in before["problems"].items():
            if pkey not in after["problems"]:
                changes.append(Change(domain, key, "resolved", old=json.dumps(problem, ensure_ascii=False)))
    return sorted(changes, key=lambda c: (c.section, c.kind))


def check(db: Database, settings: Settings) -> list[Change]:
    """Check every domain once and store what changed."""
    domains = settings.domains or queries.all_domains(db)
    mailbox = settings.imap_user if "@" in settings.imap_user else ""
    found: list[Change] = []
    for domain in domains:
        sections = dnscheck.check_domain(domain, queries.selectors_of(db, domain), mailbox, refresh=True)
        if any(s.key == "error" for s in sections):
            log.info("DNS check of %s skipped: DNS not reachable", domain)
            continue
        new = snapshot(sections)
        try:
            old = json.loads(db.get_meta(f"dns_snapshot:{domain}") or "null")
        except ValueError:
            old = None
        changes = compare(domain, old, new) if old else []
        now = int(time.time())
        with db.connect() as con:
            con.execute("INSERT INTO meta VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                        (f"dns_snapshot:{domain}", json.dumps(new, ensure_ascii=False)))
            con.executemany("INSERT INTO dns_changes (domain, section, kind, old, new, created_at) "
                            "VALUES (?,?,?,?,?,?)", [(c.domain, c.section, c.kind, c.old, c.new, now) for c in changes])
        if changes:
            log.info("DNS check of %s: %d changes", domain, len(changes))
        found += changes
    return found


SECTION_TITLES = {"dmarc": "DMARC", "spf": "SPF", "dkim": "DKIM", "mx": "MX", "mta_sts": "MTA-STS",
                  "tlsrpt": "TLS-RPT", "bimi": "BIMI"}


def problem_text(value: str) -> str:
    """Translated text of a stored problem."""
    try:
        problem = json.loads(value)
        return _(problem["text"], **problem["args"])
    except (ValueError, KeyError, TypeError, IndexError):
        return value


def describe(change: Change | dict) -> tuple[str, str]:
    """(headline, detail) of a change in the current language."""
    c = change if isinstance(change, dict) else change.__dict__
    title = SECTION_TITLES.get(c["section"], c["section"])
    if c["kind"] == "record":
        if not c["old"]:
            return _("{what}: Eintrag neu veröffentlicht", what=title), c["new"]
        if not c["new"]:
            return _("{what}: Eintrag entfernt", what=title), c["old"]
        return _("{what}: Eintrag geändert", what=title), f"{c['old']} → {c['new']}"
    if c["kind"] == "problem":
        return _("{what}: neues Problem", what=title), problem_text(c["new"])
    return _("{what}: behoben", what=title), problem_text(c["old"])


def report(db: Database, settings: Settings, changes: list[Change]) -> bool:
    """One message with all changes. Only sent if a record changed or a problem is new."""
    if not settings.notify_enabled or not any(c.kind in ("record", "problem") for c in changes):
        return False
    i18n.set_language(settings.default_language or i18n.DEFAULT)
    lines = []
    for c in changes[:15]:
        head, detail = describe(c)
        lines.append(f"{c.domain} · {head}")
        if detail:
            lines.append(f"  {detail[:300]}")
    if len(changes) > 15:
        lines.append(_("… und {n} weitere", n=len(changes) - 15))
    title = (settings.app_title or "mailreports") + ": " + _("DNS-Einträge geändert")
    data = {"dns_changes": [{"domain": c.domain, "section": c.section, "kind": c.kind,
                             "text": " ".join(describe(c))} for c in changes]}
    return notify.send_all(db, settings, title, "\n".join(lines), data)


def recent(db: Database, domain: str, limit: int = 20) -> list[dict]:
    with db.connect() as con:
        rows = con.execute("SELECT * FROM dns_changes WHERE domain = ? ORDER BY created_at DESC, id DESC LIMIT ?",
                           (domain, limit)).fetchall()
    return [dict(r) for r in rows]
