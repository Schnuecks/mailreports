# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Encryption of small secrets in the database (authenticator keys).

With SECRET_KEY set, the keys are stored encrypted with AES-256-GCM; the key itself only
lives in the configuration, never in the database. A stolen copy of the database then
contains nothing to generate codes with. Without SECRET_KEY they are stored as plain text.
"""
from __future__ import annotations

import base64
import logging
import os
import sqlite3

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

log = logging.getLogger(__name__)

PREFIX = "enc:v1:"


def _aead(secret_key: str) -> AESGCM:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"mailreports totp").derive(secret_key.encode())
    return AESGCM(key)


def seal(secret_key: str, value: str) -> str:
    if not secret_key or not value:
        return value
    nonce = os.urandom(12)
    return PREFIX + base64.urlsafe_b64encode(nonce + _aead(secret_key).encrypt(nonce, value.encode(), None)).decode()


def open_(secret_key: str, value: str) -> str:
    """Plain text of a stored value; empty if it cannot be decrypted."""
    if not value.startswith(PREFIX):
        return value
    if not secret_key:
        return ""
    try:
        data = base64.urlsafe_b64decode(value[len(PREFIX):])
        return _aead(secret_key).decrypt(data[:12], data[12:], None).decode()
    except (ValueError, InvalidTag):
        return ""


def migrate(conn: sqlite3.Connection, secret_key: str) -> None:
    """At start: encrypt existing plain keys, or warn if encrypted ones cannot be read."""
    for row in conn.execute("SELECT id, totp_secret FROM users WHERE totp_secret != ''").fetchall():
        value = row["totp_secret"]
        if value.startswith(PREFIX):
            if not open_(secret_key, value):
                log.error("Cannot decrypt the authenticator key of user %s: SECRET_KEY is missing or wrong.",
                          row["id"])
        elif secret_key:
            conn.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (seal(secret_key, value), row["id"]))
