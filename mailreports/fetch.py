# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Fetching report mails over IMAP.

Mails are never deleted. Processed mails are moved to IMAP_MOVE_TO, or – if that is
empty – flagged as seen and with the keyword $MailreportsDone. Mails without a usable
report go to IMAP_ERROR_FOLDER or get the keyword $MailreportsError. Both keywords are
skipped on the next fetch, so a mail is looked at only once.

With IMAP_READONLY the mailbox is opened read-only and nothing is changed at all; the
UIDs of processed mails are remembered in the database instead. Useful when another
program reads the same mailbox.
"""
from __future__ import annotations

import imaplib
import logging
import re
import ssl
import time
from dataclasses import dataclass, field

from .config import Settings
from .db import Database
from .ingest import Outcome, ingest_mail

log = logging.getLogger(__name__)

KW_DONE = "$MailreportsDone"
KW_ERROR = "$MailreportsError"
BATCH = 200          # mails per run; the rest follows on the next run


@dataclass
class FetchResult:
    mails: int = 0
    outcome: Outcome = field(default_factory=Outcome)
    error: str = ""


def _quote(folder: str) -> str:
    return '"' + folder.replace("\\", "\\\\").replace('"', '\\"') + '"'


def connect(settings: Settings) -> imaplib.IMAP4:
    ctx = ssl.create_default_context()
    if settings.imap_security == "ssl":
        conn = imaplib.IMAP4_SSL(settings.imap_host, settings.imap_port, ssl_context=ctx, timeout=60)
    else:
        conn = imaplib.IMAP4(settings.imap_host, settings.imap_port, timeout=60)
        if settings.imap_security == "starttls":
            conn.starttls(ssl_context=ctx)
    conn.login(settings.imap_user, settings.imap_password)
    return conn


def _ensure_folder(conn: imaplib.IMAP4, folder: str) -> None:
    typ, _ = conn.select(_quote(folder), readonly=True)
    if typ == "OK":
        return
    typ, data = conn.create(_quote(folder))
    if typ != "OK":
        raise imaplib.IMAP4.error(f"cannot create folder {folder}: {data}")
    conn.subscribe(_quote(folder))


def _move(conn: imaplib.IMAP4, uid: bytes, folder: str, capabilities: set[str]) -> None:
    if "MOVE" in capabilities:
        typ, data = conn.uid("MOVE", uid, _quote(folder))
        if typ != "OK":
            raise imaplib.IMAP4.error(f"MOVE failed: {data}")
        return
    typ, data = conn.uid("COPY", uid, _quote(folder))
    if typ != "OK":
        raise imaplib.IMAP4.error(f"COPY failed: {data}")
    conn.uid("STORE", uid, "+FLAGS.SILENT", r"(\Deleted)")
    if "UIDPLUS" in capabilities:
        conn.uid("EXPUNGE", uid)


def _finish(conn, uid: bytes, ok: bool, settings: Settings, capabilities: set[str]) -> None:
    folder = settings.imap_move_to if ok else settings.imap_error_folder
    keyword = KW_DONE if ok else KW_ERROR
    if folder:
        _move(conn, uid, folder, capabilities)
    else:
        conn.uid("STORE", uid, "+FLAGS.SILENT", f"(\\Seen {keyword})")


def fetch(db: Database, settings: Settings) -> FetchResult:
    result = FetchResult()
    try:
        conn = connect(settings)
    except (OSError, imaplib.IMAP4.error, ssl.SSLError) as exc:
        result.error = f"IMAP connection to {settings.imap_host}: {exc}"
        return result
    try:
        caps = {c.decode().upper() if isinstance(c, bytes) else str(c).upper() for c in conn.capabilities}
        readonly = settings.imap_readonly
        if not readonly:
            for folder in {settings.imap_move_to, settings.imap_error_folder} - {""}:
                _ensure_folder(conn, folder)
        typ, data = conn.select(_quote(settings.imap_folder), readonly=readonly)
        if typ != "OK":
            raise imaplib.IMAP4.error(f"cannot open folder {settings.imap_folder}: {data}")
        if readonly:
            validity = conn.response("UIDVALIDITY")[1]
            uidvalidity = (validity[0] or b"0").decode() if validity else "0"
            typ, data = conn.uid("SEARCH", None, "ALL")
        else:
            typ, data = conn.uid("SEARCH", None, f"UNKEYWORD {KW_DONE} UNKEYWORD {KW_ERROR}")
        if typ != "OK":
            raise imaplib.IMAP4.error(f"SEARCH failed: {data}")
        uids = data[0].split() if data and data[0] else []
        if readonly:
            seen = db.seen_uids(settings.imap_folder, uidvalidity)
            uids = [u for u in uids if int(u) not in seen]
        for uid in uids[:BATCH]:
            typ, parts = conn.uid("FETCH", uid, "(BODY.PEEK[])")
            raw = next((p[1] for p in parts or [] if isinstance(p, tuple) and len(p) > 1), None)
            if typ != "OK" or raw is None:
                log.warning("mail UID %s could not be fetched", uid)
                continue
            out = ingest_mail(db, raw)
            result.mails += 1
            result.outcome.merge(out)
            if readonly:
                db.mark_uid_seen(settings.imap_folder, uidvalidity, int(uid))
            else:
                _finish(conn, uid, out.found_any, settings, caps)
        if not readonly and (settings.imap_move_to or settings.imap_error_folder):
            if "UIDPLUS" not in caps and "MOVE" not in caps:
                conn.expunge()
    except (OSError, imaplib.IMAP4.error, ssl.SSLError) as exc:
        result.error = f"IMAP: {exc}"
    finally:
        try:
            conn.logout()
        except (OSError, imaplib.IMAP4.error):
            pass
    return result


_SECRET = re.compile(r"(LOGIN\s+\S+\s+)\S+", re.I)


def describe_error(text: str) -> str:
    """Error text without anything that looks like a password."""
    return _SECRET.sub(r"\1***", text)


def record_run(db: Database, result: FetchResult) -> None:
    now = str(int(time.time()))
    db.set_meta("last_fetch", now)
    db.set_meta("last_fetch_error", describe_error(result.error))
    if not result.error:
        db.set_meta("last_fetch_ok", now)
    db.set_meta("last_fetch_summary",
                f"{result.mails}|{len(result.outcome.new_dmarc)}|{len(result.outcome.new_tls)}"
                f"|{result.outcome.duplicates}|{len(result.outcome.errors)}")
