# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Time-based one-time codes (TOTP, RFC 6238) for two-factor sign-in.

Six digits, 30 seconds, SHA-1: understood by every common authenticator app.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import secrets
import sqlite3
import struct
import time
from urllib.parse import quote

import segno

from . import secretbox

STEP = 30
DIGITS = 6
WINDOW = 1   # one step before and after, in case the phone's clock is a little off


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def matching_step(secret: str, code: str, at: float | None = None) -> int | None:
    code = "".join(code.split())
    if not secret or len(code) != DIGITS or not code.isdigit():
        return None
    current = int((time.time() if at is None else at) // STEP)
    for step in range(current - WINDOW, current + WINDOW + 1):
        if hmac.compare_digest(_code(secret, step), code):
            return step
    return None


def secret_of(user: sqlite3.Row, secret_key: str) -> str:
    return secretbox.open_(secret_key, user["totp_secret"])


def verify_user_code(conn: sqlite3.Connection, user: sqlite3.Row, code: str, secret_key: str = "") -> bool:
    """Checks the user's code and accepts every code only once."""
    step = matching_step(secret_of(user, secret_key), code)
    if step is None:
        return False
    cur = conn.execute("UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?",
                       (step, user["id"], step))
    return cur.rowcount == 1


def provisioning_uri(secret: str, username: str, issuer: str) -> str:
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"


def qr_svg(uri: str) -> str:
    out = io.BytesIO()
    segno.make(uri, error="m").save(out, kind="svg", xmldecl=False, svgns=True, scale=5, border=2,
                                    svgclass="qr", dark="#1f2618", light="#ffffff")
    return out.getvalue().decode()


def format_secret(secret: str) -> str:
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
