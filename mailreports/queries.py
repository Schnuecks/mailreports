# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Read-only queries for the pages."""
from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from .db import Database
from .sources import Source, classify, classify_ip

PAGE_SIZE = 50


def since_ts(days: int) -> int:
    return int(time.time()) - days * 86400


def day_of(ts: int, tz: ZoneInfo) -> date:
    return datetime.fromtimestamp(ts, tz).date()


def day_range(days: int, tz: ZoneInfo) -> list[date]:
    today = datetime.now(tz).date()
    return [today - timedelta(days=i) for i in range(days - 1, -1, -1)]


@dataclass
class DomainSummary:
    domain: str
    messages: int = 0
    passed: int = 0
    reports: int = 0
    reporters: int = 0
    last_report: int = 0
    policy: str = ""
    sp: str = ""
    adkim: str = ""
    aspf: str = ""
    pct: str = ""
    quarantined: int = 0
    rejected: int = 0
    daily: list[tuple[date, int, int]] = field(default_factory=list)
    tls_success: int = 0
    tls_failure: int = 0

    @property
    def failed(self) -> int:
        return self.messages - self.passed

    @property
    def rate(self) -> float | None:
        return self.passed / self.messages * 100 if self.messages else None


def domain_summaries(db: Database, days: int, tz: ZoneInfo, only: list[str] | None = None) -> list[DomainSummary]:
    since = since_ts(days)
    out: dict[str, DomainSummary] = {}
    with db.connect() as con:
        for row in con.execute(
                """SELECT domain, COUNT(*) AS reports, COUNT(DISTINCT org_name) AS reporters,
                          MAX(date_end) AS last_report
                   FROM dmarc_reports WHERE date_end >= ? GROUP BY domain""", (since,)):
            out[row["domain"]] = DomainSummary(row["domain"], reports=row["reports"],
                                               reporters=row["reporters"], last_report=row["last_report"])
        for row in con.execute(
                """SELECT p.domain, p.date_begin, SUM(r.count) AS n,
                          SUM(CASE WHEN r.dmarc_pass THEN r.count ELSE 0 END) AS ok,
                          SUM(CASE WHEN r.disposition = 'quarantine' THEN r.count ELSE 0 END) AS q,
                          SUM(CASE WHEN r.disposition = 'reject' THEN r.count ELSE 0 END) AS rj
                   FROM dmarc_records r JOIN dmarc_reports p ON p.id = r.report_id
                   WHERE p.date_end >= ? GROUP BY p.id""", (since,)):
            s = out[row["domain"]]
            s.messages += row["n"] or 0
            s.passed += row["ok"] or 0
            s.quarantined += row["q"] or 0
            s.rejected += row["rj"] or 0
        # latest published policy per domain (as seen by the reporters)
        for row in con.execute(
                """SELECT domain, p, sp, adkim, aspf, pct FROM dmarc_reports d
                   WHERE date_end = (SELECT MAX(date_end) FROM dmarc_reports WHERE domain = d.domain)"""):
            if row["domain"] in out:
                s = out[row["domain"]]
                s.policy, s.sp, s.adkim, s.aspf, s.pct = row["p"], row["sp"], row["adkim"], row["aspf"], row["pct"]
        for row in con.execute(
                """SELECT p.policy_domain AS domain, SUM(p.success) AS ok, SUM(p.failure) AS bad
                   FROM tls_policies p JOIN tls_reports t ON t.id = p.report_id
                   WHERE t.date_end >= ? GROUP BY p.policy_domain""", (since,)):
            s = out.setdefault(row["domain"], DomainSummary(row["domain"]))
            s.tls_success, s.tls_failure = row["ok"] or 0, row["bad"] or 0
    for s in out.values():
        s.daily = daily_series(db, s.domain, days, tz)
    result = list(out.values())
    if only:
        order = {d: i for i, d in enumerate(only)}
        result = [s for s in result if s.domain in order]
        result.sort(key=lambda s: order[s.domain])
    else:
        result.sort(key=lambda s: (-s.messages, s.domain))
    return result


def daily_series(db: Database, domain: str, days: int, tz: ZoneInfo) -> list[tuple[date, int, int]]:
    """Messages per day (passed, failed), bucketed by the report's start."""
    buckets = {d: [0, 0] for d in day_range(days, tz)}
    with db.connect() as con:
        rows = con.execute(
            """SELECT p.date_begin, p.date_end, SUM(CASE WHEN r.dmarc_pass THEN r.count ELSE 0 END) AS ok,
                      SUM(CASE WHEN r.dmarc_pass THEN 0 ELSE r.count END) AS bad
               FROM dmarc_records r JOIN dmarc_reports p ON p.id = r.report_id
               WHERE p.domain = ? AND p.date_end >= ? GROUP BY p.id""",
            (domain, since_ts(days + 1))).fetchall()
    for row in rows:
        mid = (row["date_begin"] + row["date_end"]) // 2
        d = day_of(mid, tz)
        if d in buckets:
            buckets[d][0] += row["ok"] or 0
            buckets[d][1] += row["bad"] or 0
    return [(d, ok, bad) for d, (ok, bad) in buckets.items()]


@dataclass
class SourceRow:
    ip: str
    info: object
    messages: int = 0
    passed: int = 0
    kinds: Counter = field(default_factory=Counter)
    source: Source | None = None
    dispositions: Counter = field(default_factory=Counter)
    header_from: set = field(default_factory=set)
    selectors: set = field(default_factory=set)
    reporters: set = field(default_factory=set)
    domains: set = field(default_factory=set)

    @property
    def kind(self) -> str:
        return self.kinds.most_common(1)[0][0] if self.kinds else "unknown"

    @property
    def rate(self) -> float:
        return self.passed / self.messages * 100 if self.messages else 0.0


def sources_for(db: Database, sources: list[Source], days: int, domain: str | None = None,
                limit: int | None = None) -> list[SourceRow]:
    sql = """SELECT r.*, p.org_name, p.domain FROM dmarc_records r JOIN dmarc_reports p ON p.id = r.report_id
             WHERE p.date_end >= ?"""
    args: list = [since_ts(days)]
    if domain:
        sql += " AND p.domain = ?"
        args.append(domain)
    with db.connect() as con:
        rows = con.execute(sql, args).fetchall()
    info = db.ip_info(sorted({r["source_ip"] for r in rows}))
    out: dict[str, SourceRow] = {}
    for r in rows:
        ip = r["source_ip"]
        s = out.get(ip)
        if s is None:
            s = out[ip] = SourceRow(ip, info.get(ip))
        verdict = classify(sources, r, s.info)
        s.messages += r["count"]
        s.passed += r["count"] if r["dmarc_pass"] else 0
        s.kinds[verdict.kind] += r["count"]
        if verdict.source and not s.source:
            s.source = verdict.source
        s.dispositions[r["disposition"]] += r["count"]
        if r["header_from"]:
            s.header_from.add(r["header_from"])
        s.reporters.add(r["org_name"])
        s.domains.add(r["domain"])
        for sig in json.loads(r["dkim"] or "[]"):
            if sig.get("result") == "pass" and sig.get("selector"):
                s.selectors.add(f"{sig['selector']} ({sig.get('domain', '')})")
    if not out:
        return []
    for s in out.values():
        if not s.source:
            s.source = classify_ip(sources, s.ip, s.info)
    result = sorted(out.values(), key=lambda s: (-s.messages, s.ip))
    return result[:limit] if limit else result


def list_reports(db: Database, days: int, domain: str = "", org: str = "", failed_only: bool = False,
                 page: int = 1) -> tuple[list, int]:
    where = ["p.date_end >= ?"]
    args: list = [since_ts(days)]
    if domain:
        where.append("p.domain = ?")
        args.append(domain)
    if org:
        where.append("p.org_name = ?")
        args.append(org)
    having = " HAVING failed > 0" if failed_only else ""
    base = f"""SELECT p.*, COALESCE(SUM(r.count), 0) AS messages,
                      COALESCE(SUM(CASE WHEN r.dmarc_pass THEN 0 ELSE r.count END), 0) AS failed,
                      COUNT(r.id) AS records
               FROM dmarc_reports p LEFT JOIN dmarc_records r ON r.report_id = p.id
               WHERE {' AND '.join(where)} GROUP BY p.id{having}"""
    with db.connect() as con:
        total = con.execute(f"SELECT COUNT(*) FROM ({base})", args).fetchone()[0]
        rows = con.execute(f"{base} ORDER BY p.date_begin DESC, p.id DESC LIMIT ? OFFSET ?",
                           [*args, PAGE_SIZE, (page - 1) * PAGE_SIZE]).fetchall()
    return rows, total


def report_detail(db: Database, report_id: int):
    with db.connect() as con:
        rep = con.execute("SELECT * FROM dmarc_reports WHERE id = ?", (report_id,)).fetchone()
        if not rep:
            return None, []
        records = con.execute(
            "SELECT * FROM dmarc_records WHERE report_id = ? ORDER BY dmarc_pass, count DESC", (report_id,)
        ).fetchall()
    return rep, records


def organisations(db: Database) -> list[str]:
    with db.connect() as con:
        return [r[0] for r in con.execute(
            "SELECT DISTINCT org_name FROM dmarc_reports ORDER BY org_name COLLATE NOCASE")]


def all_domains(db: Database) -> list[str]:
    with db.connect() as con:
        return [r[0] for r in con.execute(
            "SELECT domain FROM dmarc_reports UNION SELECT policy_domain FROM tls_policies ORDER BY 1")]


# ---------------------------------------------------------------- TLS

def tls_overview(db: Database, days: int) -> list[dict]:
    """Per policy domain and type: sessions and failure types."""
    since = since_ts(days)
    out: dict[tuple, dict] = {}
    with db.connect() as con:
        for row in con.execute(
                """SELECT p.policy_domain, p.policy_type, SUM(p.success) AS ok, SUM(p.failure) AS bad,
                          COUNT(DISTINCT t.id) AS reports, COUNT(DISTINCT t.org_name) AS reporters
                   FROM tls_policies p JOIN tls_reports t ON t.id = p.report_id
                   WHERE t.date_end >= ? GROUP BY p.policy_domain, p.policy_type
                   ORDER BY p.policy_domain, p.policy_type""", (since,)):
            out[(row["policy_domain"], row["policy_type"])] = dict(row) | {"types": Counter(), "mx_list": set()}
        for row in con.execute(
                """SELECT p.policy_domain, p.policy_type, f.result_type, SUM(f.failed_session_count) AS n
                   FROM tls_failures f JOIN tls_policies p ON p.id = f.policy_id
                   JOIN tls_reports t ON t.id = p.report_id
                   WHERE t.date_end >= ? GROUP BY 1, 2, 3""", (since,)):
            key = (row["policy_domain"], row["policy_type"])
            if key in out:
                out[key]["types"][row["result_type"]] += row["n"] or 0
        for row in con.execute(
                """SELECT DISTINCT p.policy_domain, p.policy_type, p.mx_hosts FROM tls_policies p
                   JOIN tls_reports t ON t.id = p.report_id WHERE t.date_end >= ?""", (since,)):
            key = (row["policy_domain"], row["policy_type"])
            if key in out:
                out[key]["mx_list"].update(json.loads(row["mx_hosts"] or "[]"))
    return list(out.values())


def list_tls(db: Database, days: int, domain: str = "", failed_only: bool = False, page: int = 1) -> tuple[list, int]:
    where = ["t.date_end >= ?"]
    args: list = [since_ts(days)]
    if domain:
        where.append("p.policy_domain = ?")
        args.append(domain)
    having = " HAVING failure > 0" if failed_only else ""
    base = f"""SELECT t.*, SUM(p.success) AS success, SUM(p.failure) AS failure,
                      GROUP_CONCAT(DISTINCT p.policy_domain) AS domains,
                      GROUP_CONCAT(DISTINCT p.policy_type) AS types
               FROM tls_reports t LEFT JOIN tls_policies p ON p.report_id = t.id
               WHERE {' AND '.join(where)} GROUP BY t.id{having}"""
    with db.connect() as con:
        total = con.execute(f"SELECT COUNT(*) FROM ({base})", args).fetchone()[0]
        rows = con.execute(f"{base} ORDER BY t.date_begin DESC, t.id DESC LIMIT ? OFFSET ?",
                           [*args, PAGE_SIZE, (page - 1) * PAGE_SIZE]).fetchall()
    return rows, total


def tls_detail(db: Database, report_id: int):
    with db.connect() as con:
        rep = con.execute("SELECT * FROM tls_reports WHERE id = ?", (report_id,)).fetchone()
        if not rep:
            return None, []
        policies = [dict(p) for p in con.execute(
            "SELECT * FROM tls_policies WHERE report_id = ? ORDER BY policy_domain, policy_type", (report_id,))]
        failures = defaultdict(list)
        for f in con.execute(
                """SELECT f.* FROM tls_failures f JOIN tls_policies p ON p.id = f.policy_id
                   WHERE p.report_id = ? ORDER BY f.failed_session_count DESC""", (report_id,)):
            failures[f["policy_id"]].append(f)
    for p in policies:
        p["failures"] = failures.get(p["id"], [])
    return rep, policies


def recent_mails(db: Database, limit: int = 50) -> list:
    with db.connect() as con:
        return con.execute("SELECT * FROM mails ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def counts(db: Database) -> dict:
    with db.connect() as con:
        return {
            "dmarc": con.execute("SELECT COUNT(*) FROM dmarc_reports").fetchone()[0],
            "tls": con.execute("SELECT COUNT(*) FROM tls_reports").fetchone()[0],
            "records": con.execute("SELECT COUNT(*) FROM dmarc_records").fetchone()[0],
            "mails": con.execute("SELECT COUNT(*) FROM mails").fetchone()[0],
            "mail_errors": con.execute("SELECT COUNT(*) FROM mails WHERE status = 'error'").fetchone()[0],
        }


@dataclass
class Problem:
    record: dict
    report: dict
    reporters: set
    first: int
    last: int


def problems(db: Database, days: int, limit: int = 8) -> list[Problem]:
    """Failed records of the period, merged per domain, IP and outcome (newest first)."""
    with db.connect() as con:
        rows = con.execute(
            """SELECT r.*, p.domain, p.org_name, p.date_begin, p.date_end, p.adkim, p.aspf, p.id AS rep_id
               FROM dmarc_records r JOIN dmarc_reports p ON p.id = r.report_id
               WHERE p.date_end >= ? AND r.dmarc_pass = 0 ORDER BY p.date_begin DESC""",
            (since_ts(days),)).fetchall()
    merged: dict[tuple, Problem] = {}
    for r in rows:
        key = (r["domain"], r["source_ip"], r["disposition"])
        p = merged.get(key)
        if p is None:
            report = {"id": r["rep_id"], "domain": r["domain"], "adkim": r["adkim"], "aspf": r["aspf"],
                      "org_name": r["org_name"], "date_begin": r["date_begin"], "date_end": r["date_end"]}
            merged[key] = Problem(dict(r), report, {r["org_name"]}, r["date_begin"], r["date_end"])
        else:
            p.record["count"] += r["count"]
            p.reporters.add(r["org_name"])
            p.first = min(p.first, r["date_begin"])
    return list(merged.values())[:limit]
