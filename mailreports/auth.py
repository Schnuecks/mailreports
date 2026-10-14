# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Built-in sign-in with one password, for running without a login proxy.

ADMIN_PASSWORD (or ADMIN_PASSWORD_FILE) is either the password itself or an Argon2 hash
created with `python -m mailreports hash-password`. A successful sign-in sets a signed,
HttpOnly session cookie; the signing key is created once in DATA_DIR. Failed attempts are
limited per client address.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

COOKIE = "mailreports_session"
SESSION_DAYS = 30
MAX_FAILURES = 5          # per client address ...
FAILURE_WINDOW = 15 * 60  # ... within this many seconds

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def check_password(configured: str, given: str) -> bool:
    if not configured or not given:
        return False
    if configured.startswith("$argon2"):
        try:
            return _hasher.verify(configured, given)
        except (VerificationError, InvalidHashError):
            return False
    return hmac.compare_digest(configured.encode(), given.encode())


def load_key(data_dir: Path) -> bytes:
    """Signing key for session cookies, created on first start (0600)."""
    path = data_dir / "session.key"
    try:
        key = path.read_bytes()
        if len(key) >= 32:
            return key
    except FileNotFoundError:
        pass
    key = secrets.token_bytes(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


class Sessions:
    def __init__(self, key: bytes, password: str):
        # The password (or its hash) is part of the signature: changing it signs everybody out
        self.key = hmac.new(key, password.encode(), hashlib.sha256).digest()
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _sign(self, payload: bytes) -> str:
        return base64.urlsafe_b64encode(hmac.new(self.key, payload, hashlib.sha256).digest()).decode().rstrip("=")

    def create(self) -> str:
        payload = f"{int(time.time()) + SESSION_DAYS * 86400}.{secrets.token_hex(8)}".encode()
        return base64.urlsafe_b64encode(payload).decode().rstrip("=") + "." + self._sign(payload)

    def valid(self, token: str | None) -> bool:
        if not token or token.count(".") != 1:
            return False
        data, sig = token.split(".")
        try:
            payload = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
            expires = int(payload.split(b".")[0])
        except (ValueError, IndexError):
            return False
        return hmac.compare_digest(sig, self._sign(payload)) and expires > time.time()

    # ------------------------------------------------------------ rate limit

    def blocked(self, client: str) -> bool:
        now = time.time()
        with self._lock:
            recent = [t for t in self._failures.get(client, []) if t > now - FAILURE_WINDOW]
            self._failures[client] = recent
            return len(recent) >= MAX_FAILURES

    def failed(self, client: str) -> None:
        with self._lock:
            self._failures.setdefault(client, []).append(time.time())

    def succeeded(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)
