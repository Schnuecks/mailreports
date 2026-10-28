# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""SQLite storage. One file in DATA_DIR, opened per use (WAL, safe for the fetch thread)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import zlib
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

CREATE TABLE IF NOT EXISTS raw_reports (
    kind TEXT NOT NULL,               -- dmarc or tls
    report_id INTEGER NOT NULL,
    data BLOB NOT NULL,               -- original file, zlib-compressed
    PRIMARY KEY (kind, report_id)
);

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

CREATE TABLE IF NOT EXISTS imap_seen (
    folder TEXT NOT NULL,
    uidvalidity TEXT NOT NULL,
    uid INTEGER NOT NULL,
    PRIMARY KEY (folder, uidvalidity, uid)
);

-- Accounts and sign-in
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    is_admin INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    totp_secret TEXT NOT NULL DEFAULT '',
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    oidc_sub TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    client_info TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_logins (
    id INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at INTEGER
);

CREATE TABLE IF NOT EXISTS passkeys (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    challenge BLOB NOT NULL,
    purpose TEXT NOT NULL,
    user_id INTEGER,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_flows (
    id INTEGER PRIMARY KEY,
    state_hash TEXT NOT NULL UNIQUE,
    nonce TEXT NOT NULL,
    verifier TEXT NOT NULL,
    next TEXT NOT NULL,
    link_user_id INTEGER,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    user_id INTEGER,
    ip TEXT NOT NULL,
    success INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS login_events_created ON login_events (created_at);

CREATE TABLE IF NOT EXISTS notifications (
    key TEXT PRIMARY KEY,
    last_sent INTEGER NOT NULL
);

-- Known senders added in the app (in addition to sources.toml)
CREATE TABLE IF NOT EXISTS known_sources (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    ips TEXT NOT NULL DEFAULT '[]',
    ptr TEXT NOT NULL DEFAULT '[]',
    asn TEXT NOT NULL DEFAULT '[]',
    dkim_selectors TEXT NOT NULL DEFAULT '[]',
    dkim_domains TEXT NOT NULL DEFAULT '[]',
    note TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Changes found by the daily DNS check
CREATE TABLE IF NOT EXISTS dns_changes (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    section TEXT NOT NULL,
    kind TEXT NOT NULL,            -- record, problem, resolved
    old TEXT NOT NULL DEFAULT '',
    new TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS dns_changes_domain ON dns_changes (domain, created_at);
"""

_lock = threading.Lock()


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as con:
            con.executescript(SCHEMA)
            con.execute("INSERT OR IGNORE INTO meta VALUES ('schema', ?)", (str(SCHEMA_VERSION),))
            # Columns added after a table first appeared (test build 0.2.0-rc.1)
            if "link_user_id" not in {r[1] for r in con.execute("PRAGMA table_info(oidc_flows)")}:
                con.execute("ALTER TABLE oidc_flows ADD COLUMN link_user_id INTEGER")

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

    def add_dmarc(self, rep: DmarcReport, mail_id: int | None = None, raw: bytes = b"") -> int | None:
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
            self._store_raw(con, "dmarc", rid, raw)
            con.executemany(
                """INSERT INTO dmarc_records
                   (report_id, source_ip, count, disposition, dkim_eval, spf_eval, dmarc_pass,
                    header_from, envelope_from, envelope_to, reasons, dkim, spf)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [(rid, r.source_ip, r.count, r.disposition, r.dkim_eval, r.spf_eval, int(r.dmarc_pass),
                  r.header_from, r.envelope_from, r.envelope_to,
                  json.dumps(r.reasons), json.dumps(r.dkim), json.dumps(r.spf)) for r in rep.records])
            return rid

    def add_tls(self, rep: TlsReport, mail_id: int | None = None, raw: bytes = b"") -> int | None:
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
            self._store_raw(con, "tls", rid, raw)
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

    @staticmethod
    def _store_raw(con, kind: str, rid: int, raw: bytes) -> None:
        if raw:
            con.execute("INSERT OR REPLACE INTO raw_reports VALUES (?, ?, ?)", (kind, rid, zlib.compress(raw, 9)))

    def has_raw(self, kind: str, rid: int) -> bool:
        with self.connect() as con:
            row = con.execute("SELECT 1 FROM raw_reports WHERE kind = ? AND report_id = ?", (kind, rid)).fetchone()
        return row is not None

    def raw_report(self, kind: str, rid: int) -> bytes | None:
        with self.connect() as con:
            row = con.execute("SELECT data FROM raw_reports WHERE kind = ? AND report_id = ?", (kind, rid)).fetchone()
        return zlib.decompress(row[0]) if row else None

    def housekeeping(self, retention_days: int) -> dict:
        """Deletes old data. retention_days 0 keeps reports forever."""
        now = int(time.time())
        out = {"dmarc": 0, "tls": 0}
        with self.connect() as con:
            if retention_days > 0:
                cutoff = now - retention_days * 86400
                out["dmarc"] = con.execute("DELETE FROM dmarc_reports WHERE date_end < ?", (cutoff,)).rowcount
                out["tls"] = con.execute("DELETE FROM tls_reports WHERE date_end < ?", (cutoff,)).rowcount
            for kind, table in (("dmarc", "dmarc_reports"), ("tls", "tls_reports")):
                con.execute(f"DELETE FROM raw_reports WHERE kind = ? AND report_id NOT IN (SELECT id FROM {table})",
                            (kind,))
            con.execute("DELETE FROM mails WHERE processed_at < ?", (now - 180 * 86400,))
            con.execute("DELETE FROM login_events WHERE created_at < ?", (now - 365 * 86400,))
            con.execute("DELETE FROM dns_changes WHERE created_at < ?", (now - 365 * 86400,))
            con.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            con.execute("DELETE FROM pending_logins WHERE expires_at < ?", (now,))
            con.execute("DELETE FROM webauthn_challenges WHERE expires_at < ?", (now,))
            con.execute("DELETE FROM oidc_flows WHERE expires_at < ?", (now,))
            con.execute("""DELETE FROM ip_info WHERE updated_at < ? AND ip NOT IN (
                SELECT source_ip FROM dmarc_records UNION SELECT sending_mta_ip FROM tls_failures)""",
                        (now - 30 * 86400,))
        return out

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

    # ------------------------------------------------------------ read-only IMAP

    def seen_uids(self, folder: str, uidvalidity: str) -> set[int]:
        with self.connect() as con:
            return {r[0] for r in con.execute(
                "SELECT uid FROM imap_seen WHERE folder = ? AND uidvalidity = ?", (folder, uidvalidity))}

    def mark_uid_seen(self, folder: str, uidvalidity: str, uid: int) -> None:
        with self.connect() as con:
            con.execute("INSERT OR IGNORE INTO imap_seen VALUES (?, ?, ?)", (folder, uidvalidity, uid))

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
