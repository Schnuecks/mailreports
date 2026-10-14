# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Turns a mail (or a file) into stored reports."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from . import parsing
from .db import Database

log = logging.getLogger(__name__)


@dataclass
class Outcome:
    new_dmarc: list[int] = field(default_factory=list)
    new_tls: list[int] = field(default_factory=list)
    duplicates: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def found_any(self) -> bool:
        return bool(self.new_dmarc or self.new_tls or self.duplicates)

    def merge(self, other: Outcome) -> None:
        self.new_dmarc += other.new_dmarc
        self.new_tls += other.new_tls
        self.duplicates += other.duplicates
        self.errors += other.errors

    @property
    def status(self) -> str:
        if self.new_dmarc or self.new_tls:
            return "new"
        if self.duplicates:
            return "duplicate"
        return "error" if self.errors else "empty"


def _ours(domain: str, domains: list[str] | None) -> bool:
    """With DOMAINS set, reports for other domains are not stored: the report address is public
    and anybody can send made-up reports to it."""
    if not domains:
        return True
    domain = domain.lower().rstrip(".")
    return any(domain == d or domain.endswith("." + d) for d in domains)


def ingest_payload(db: Database, payload: parsing.Payload, mail_id: int | None = None,
                   budget: parsing.Budget | None = None, domains: list[str] | None = None) -> Outcome:
    out = Outcome()
    try:
        files = parsing.unpack(payload, budget=budget)
    except parsing.ReportError as exc:
        out.errors.append(f"{payload.name}: {exc}")
        return out
    for f in files:
        kind = parsing.kind_of(f.data)
        try:
            if kind == "dmarc":
                report = parsing.parse_dmarc(f.data)
                if not _ours(report.domain, domains):
                    out.errors.append(f"{f.name}: report for {report.domain[:100]}, not in DOMAINS")
                    continue
                rid = db.add_dmarc(report, mail_id, f.data)
                if rid is None:
                    out.duplicates += 1
                else:
                    out.new_dmarc.append(rid)
            elif kind == "tls":
                tls = parsing.parse_tls(f.data)
                if not any(_ours(p.policy_domain, domains) for p in tls.policies):
                    out.errors.append(f"{f.name}: TLS report for other domains, not in DOMAINS")
                    continue
                rid = db.add_tls(tls, mail_id, f.data)
                if rid is None:
                    out.duplicates += 1
                else:
                    out.new_tls.append(rid)
            else:
                out.errors.append(f"{f.name}: neither XML nor JSON")
        except parsing.ReportError as exc:
            out.errors.append(f"{f.name}: {exc}")
    return out


def ingest_mail(db: Database, raw: bytes, domains: list[str] | None = None) -> Outcome:
    """Store all reports of one mail and log the mail."""
    try:
        msg = parsing.parse_mail(raw)
        message_id = str(msg.get("Message-ID", "") or "")
        subject = str(msg.get("Subject", "") or "")
        sender = str(msg.get("From", "") or "")
        payloads = parsing.attachments(msg)
    except Exception as exc:  # a mail the email package cannot read must not stop the fetch
        log.warning("unreadable mail: %s", exc)
        db.log_mail("", "", "", "error", f"unreadable mail: {exc}")
        return Outcome(errors=[f"unreadable mail: {exc}"])
    mail_id = db.log_mail(message_id, subject[:300], sender[:300], "pending", "")
    out = Outcome()
    budget = parsing.Budget()   # one limit for all attachments of the mail
    for payload in payloads:
        out.merge(ingest_payload(db, payload, mail_id, budget, domains))
    if not payloads:
        out.errors.append("no attachment")
    detail = "; ".join(out.errors)[:2000]
    with db.connect() as con:
        con.execute("UPDATE mails SET status = ?, detail = ? WHERE id = ?", (out.status, detail, mail_id))
    return out
