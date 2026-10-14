# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""SQLite storage. One file in DATA_DIR, opened per use (WAL, safe for the fetch thread)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .parsing import DmarcReport, TlsReport

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS dmarc_reports (
    id INTEGER PRIMARY KEY,
    org_name TEXT NOT NULL,
    org_email TEXT,
    report_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    date_begin INTEGER NOT NULL,
    date_end INTEGER NOT NULL,
    adkim TEXT, aspf TEXT, p TEXT, sp TEXT, pct TEXT, fo TEXT, np TEXT,
    errors TEXT,
    mail_id INTEGER,
    received_at INTEGER NOT NULL,
    UNIQUE (org_name, report_id)
);
CREATE INDEX IF NOT EXISTS dmarc_reports_domain ON dmarc_reports (domain, date_begin);

CREATE TABLE IF NOT EXISTS dmarc_records (
    id INTEGER PRIMARY KEY,
    report_id INTEGER NOT NULL REFERENCES dmarc_reports (id) ON DELETE CASCADE,
    source_ip TEXT NOT NULL,
    count INTEGER NOT NULL,
    disposition TEXT,
    dkim_eval TEXT,
    spf_eval TEXT,
    dmarc_pass INTEGER NOT NULL,
    header_from TEXT,
    envelope_from TEXT,
    envelope_to TEXT,
    reasons TEXT,
    dkim TEXT,
    spf TEXT
);
CREATE INDEX IF NOT EXISTS dmarc_records_report ON dmarc_records (report_id);
CREATE INDEX IF NOT EXISTS dmarc_records_ip ON dmarc_records (source_ip);

CREATE TABLE IF NOT EXISTS tls_reports (
    id INTEGER PRIMARY KEY,
    org_name TEXT NOT NULL,
    report_id TEXT NOT NULL,
    date_begin INTEGER NOT NULL,
    date_end INTEGER NOT NULL,
    contact TEXT,
    mail_id INTEGER,
    received_at INTEGER NOT NULL,
    UNIQUE (org_name, report_id)
);

CREATE TABLE IF NOT EXISTS tls_policies (
    id INTEGER PRIMARY KEY,
    report_id INTEGER NOT NULL REFERENCES tls_reports (id) ON DELETE CASCADE,
    policy_type TEXT,
    policy_domain TEXT,
    policy_strings TEXT,
    mx_hosts TEXT,
    success INTEGER NOT NULL,
    failure INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tls_policies_report ON tls_policies (report_id);
CREATE INDEX IF NOT EXISTS tls_policies_domain ON tls_policies (policy_domain);

CREATE TABLE IF NOT EXISTS tls_failures (
    id INTEGER PRIMARY KEY,
    policy_id INTEGER NOT NULL REFERENCES tls_policies (id) ON DELETE CASCADE,
    result_type TEXT,
    failed_session_count INTEGER,
    sending_mta_ip TEXT,
    receiving_mx_hostname TEXT,
    receiving_mx_helo TEXT,
    receiving_ip TEXT,
    additional_information TEXT,
    failure_reason_code TEXT
);
CREATE INDEX IF NOT EXISTS tls_failures_policy ON tls_failures (policy_id);

CREATE TABLE IF NOT EXISTS mails (
    id INTEGER PRIMARY KEY,
    message_id TEXT,
    subject TEXT,
    sender TEXT,
    status TEXT NOT NULL,          -- new, duplicate, error, empty
    detail TEXT,
    processed_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mails_processed ON mails (processed_at);

CREATE TABLE IF NOT EXISTS ip_info (
    ip TEXT PRIMARY KEY,
    ptr TEXT,
    ptr_confirmed INTEGER,
    country TEXT,
    country_names TEXT,
    city TEXT,
    asn INTEGER,
    as_org TEXT,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    key TEXT PRIMARY KEY,
    last_sent INTEGER NOT NULL
);
"""

_lock = threading.Lock()


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as con:
            con.executescript(SCHEMA)
            con.execute("INSERT OR IGNORE INTO meta VALUES ('schema', ?)", (str(SCHEMA_VERSION),))

    @contextmanager
    def connect(self):
        con = sqlite3.connect(self.path, timeout=30)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON")
        con.execute("PRAGMA journal_mode = WAL")
        try:
            with con:
                yield con
        finally:
            con.close()

    # ------------------------------------------------------------ meta

    def get_meta(self, key: str, default: str = "") -> str:
        with self.connect() as con:
            row = con.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        with self.connect() as con:
            con.execute("INSERT INTO meta VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                        (key, value))

    # ------------------------------------------------------------ storing

    def log_mail(self, message_id: str, subject: str, sender: str, status: str, detail: str) -> int:
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO mails (message_id, subject, sender, status, detail, processed_at) VALUES (?,?,?,?,?,?)",
                (message_id, subject, sender, status, detail, int(time.time())))
            return cur.lastrowid

    def add_dmarc(self, rep: DmarcReport, mail_id: int | None = None) -> int | None:
        """Store a report; None if it is already known (same organisation and report id)."""
        with _lock, self.connect() as con:
            cur = con.execute(
                """INSERT OR IGNORE INTO dmarc_reports
                   (org_name, org_email, report_id, domain, date_begin, date_end,
                    adkim, aspf, p, sp, pct, fo, np, errors, mail_id, received_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rep.org_name, rep.org_email, rep.report_id, rep.domain, rep.date_begin, rep.date_end,
                 *(rep.policy.get(k, "") for k in ("adkim", "aspf", "p", "sp", "pct", "fo", "np")),
                 json.dumps(rep.errors) if rep.errors else None, mail_id, int(time.time())))
            if cur.rowcount == 0:
                return None
            rid = cur.lastrowid
            con.executemany(
                """INSERT INTO dmarc_records
                   (report_id, source_ip, count, disposition, dkim_eval, spf_eval, dmarc_pass,
                    header_from, envelope_from, envelope_to, reasons, dkim, spf)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [(rid, r.source_ip, r.count, r.disposition, r.dkim_eval, r.spf_eval, int(r.dmarc_pass),
                  r.header_from, r.envelope_from, r.envelope_to,
                  json.dumps(r.reasons), json.dumps(r.dkim), json.dumps(r.spf)) for r in rep.records])
            return rid

    def add_tls(self, rep: TlsReport, mail_id: int | None = None) -> int | None:
        with _lock, self.connect() as con:
            cur = con.execute(
                """INSERT OR IGNORE INTO tls_reports
                   (org_name, report_id, date_begin, date_end, contact, mail_id, received_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (rep.org_name, rep.report_id, rep.date_begin, rep.date_end, rep.contact, mail_id,
                 int(time.time())))
            if cur.rowcount == 0:
                return None
            rid = cur.lastrowid
            for pol in rep.policies:
                pid = con.execute(
                    """INSERT INTO tls_policies
                       (report_id, policy_type, policy_domain, policy_strings, mx_hosts, success, failure)
                       VALUES (?,?,?,?,?,?,?)""",
                    (rid, pol.policy_type, pol.policy_domain, json.dumps(pol.policy_strings),
                     json.dumps(pol.mx_hosts), pol.success, pol.failure)).lastrowid
                con.executemany(
                    """INSERT INTO tls_failures
                       (policy_id, result_type, failed_session_count, sending_mta_ip, receiving_mx_hostname,
                        receiving_mx_helo, receiving_ip, additional_information, failure_reason_code)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    [(pid, f.result_type, f.failed_session_count, f.sending_mta_ip, f.receiving_mx_hostname,
                      f.receiving_mx_helo, f.receiving_ip, f.additional_information, f.failure_reason_code)
                     for f in pol.failures])
            return rid

    # ------------------------------------------------------------ IP information

    def ip_info(self, ips: list[str]) -> dict[str, sqlite3.Row]:
        if not ips:
            return {}
        out = {}
        with self.connect() as con:
            for i in range(0, len(ips), 500):
                chunk = ips[i:i + 500]
                marks = ",".join("?" * len(chunk))
                for row in con.execute(f"SELECT * FROM ip_info WHERE ip IN ({marks})", chunk):
                    out[row["ip"]] = row
        return out

    def save_ip_info(self, ip: str, info: dict) -> None:
        with self.connect() as con:
            con.execute(
                """INSERT INTO ip_info (ip, ptr, ptr_confirmed, country, country_names, city, asn, as_org, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT (ip) DO UPDATE SET ptr=excluded.ptr, ptr_confirmed=excluded.ptr_confirmed,
                     country=excluded.country, country_names=excluded.country_names, city=excluded.city,
                     asn=excluded.asn, as_org=excluded.as_org, updated_at=excluded.updated_at""",
                (ip, info.get("ptr"), info.get("ptr_confirmed"), info.get("country"),
                 json.dumps(info["country_names"]) if info.get("country_names") else None, info.get("city"),
                 info.get("asn"), info.get("as_org"), int(time.time())))

    def ips_without_info(self, max_age_days: int = 30) -> list[str]:
        cutoff = int(time.time()) - max_age_days * 86400
        with self.connect() as con:
            rows = con.execute(
                """SELECT ip FROM (
                       SELECT source_ip AS ip FROM dmarc_records
                       UNION SELECT sending_mta_ip FROM tls_failures WHERE sending_mta_ip != ''
                   ) LEFT JOIN ip_info USING (ip)
                   WHERE ip_info.ip IS NULL OR ip_info.updated_at < ?""", (cutoff,)).fetchall()
        return [r["ip"] for r in rows if r["ip"]]

    # ------------------------------------------------------------ notifications

    def notified_recently(self, key: str, cooldown_s: int) -> bool:
        with self.connect() as con:
            row = con.execute("SELECT last_sent FROM notifications WHERE key = ?", (key,)).fetchone()
        return bool(row) and row["last_sent"] > time.time() - cooldown_s

    def mark_notified(self, keys: list[str]) -> None:
        now = int(time.time())
        with self.connect() as con:
            con.executemany(
                "INSERT INTO notifications VALUES (?, ?) "
                "ON CONFLICT (key) DO UPDATE SET last_sent = excluded.last_sent",
                [(k, now) for k in keys])
