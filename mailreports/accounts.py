# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""User accounts: passwords, sessions, the first-run setup code, failed sign-in limits,
the second sign-in step and recovery codes.

Session tokens, setup and recovery codes are stored only as SHA-256 hashes.
"""
from __future__ import annotations

import contextlib
import hashlib
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .i18n import N_

_hasher = PasswordHasher()
# Checked for unknown usernames so the response time does not reveal whether a name exists
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 10
USERNAME_MAX = 64
SESSION_SECONDS = 30 * 86400
PENDING_SECONDS = 300
PENDING_MAX_ATTEMPTS = 5
RECOVERY_CODES = 8
# Without characters that are easy to confuse (0/O, 1/I), so codes can be typed from the log
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def now() -> int:
    return int(time.time())


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def password_problem(password: str) -> str | None:
    """German message (translation key) or None."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return N_("Das Passwort muss mindestens 10 Zeichen lang sein.")
    if len(password) > 1024:
        return N_("Das Passwort ist zu lang.")
    return None


def username_problem(username: str) -> str | None:
    if not username:
        return N_("Bitte einen Benutzernamen eingeben.")
    if len(username) > USERNAME_MAX:
        return N_("Der Benutzername ist zu lang.")
    if not all(c.isalnum() or c in "._-@" for c in username):
        return N_("Der Benutzername darf nur Buchstaben, Ziffern und . _ - @ enthalten.")
    return None


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> sqlite3.Row | None:
    """The enabled user if the password is correct, otherwise None."""
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        with contextlib.suppress(VerificationError):
            _hasher.verify(_DUMMY_HASH, password)
        return None
    try:
        _hasher.verify(row["password_hash"], password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return None
    if _hasher.check_needs_rehash(row["password_hash"]):
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), row["id"]))
    return row if row["enabled"] else None


def create_user(conn: sqlite3.Connection, username: str, password: str, *, is_admin: bool = False,
                display_name: str = "", email: str = "", password_hash: str = "") -> int:
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, display_name, email, is_admin, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (username, password_hash or hash_password(password), display_name, email, int(is_admin), now()))
    return int(cur.lastrowid)


def set_password(conn: sqlite3.Connection, user_id: int, password: str) -> None:
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user_id))
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def has_users(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def admin_count(conn: sqlite3.Connection, exclude: int | None = None) -> int:
    return conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND enabled = 1 AND id != ?",
                        (exclude or 0,)).fetchone()[0]


# ---------------------------------------------------------------- first-run setup

SETUP_KEY = "setup_code"


def setup_code(conn: sqlite3.Connection) -> str:
    """Setup code while there is no account. Kept in the database so the log, the command
    line and the web page know the same code."""
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (SETUP_KEY,)).fetchone()
    if row:
        return row["value"]
    code = "-".join("".join(secrets.choice(_ALPHABET) for _ in range(4)) for _ in range(3))
    conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)", (SETUP_KEY, code))
    return conn.execute("SELECT value FROM meta WHERE key = ?", (SETUP_KEY,)).fetchone()[0]


def setup_code_valid(conn: sqlite3.Connection, code: str) -> bool:
    wanted = setup_code(conn).replace("-", "")
    given = "".join(code.upper().split()).replace("-", "")
    return secrets.compare_digest(given.encode(), wanted.encode())


def clear_setup_code(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM meta WHERE key = ?", (SETUP_KEY,))


# ---------------------------------------------------------------- sessions

def start_session(conn: sqlite3.Connection, user_id: int, ip: str, client_info: str) -> str:
    token = secrets.token_urlsafe(32)
    ts = now()
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf, ip, client_info, created_at, last_used_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (token_hash(token), user_id, secrets.token_urlsafe(24), ip, client_info[:200], ts, ts, ts + SESSION_SECONDS))
    conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (ts, user_id))
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (ts,))
    return token


def resolve_session(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    """User of a session (with the session's columns as s_id, s_csrf), extended while in use."""
    if not token:
        return None
    row = conn.execute(
        "SELECT u.*, s.id AS s_id, s.csrf AS s_csrf, s.last_used_at AS s_last_used_at,"
        " s.expires_at AS s_expires_at FROM sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash = ?", (token_hash(token),)).fetchone()
    ts = now()
    if row is None or row["s_expires_at"] < ts or not row["enabled"]:
        return None
    if ts - row["s_last_used_at"] >= 60:   # at most one write per minute
        conn.execute("UPDATE sessions SET last_used_at = ?, expires_at = ? WHERE id = ?",
                     (ts, ts + SESSION_SECONDS, row["s_id"]))
    return row


def end_session(conn: sqlite3.Connection, token: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))


def sessions_of(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM sessions WHERE user_id = ? AND expires_at >= ? ORDER BY last_used_at DESC",
                        (user_id, now())).fetchall()


# ---------------------------------------------------------------- failed sign-ins

class LoginLimiter:
    """Counts failed sign-ins per address and per username in memory (empty after a restart)."""

    def __init__(self, max_ip: int = 10, max_user: int = 5, window: int = 900):
        self.max_ip, self.max_user, self.window = max_ip, max_user, window
        self._lock = threading.Lock()
        self._fails: dict[str, deque[float]] = defaultdict(deque)

    def _count(self, key: str, ts: float) -> int:
        q = self._fails.get(key)
        if not q:
            return 0
        while q and q[0] < ts - self.window:
            q.popleft()
        if not q:
            del self._fails[key]
        return len(q)

    def blocked(self, ip: str, username: str = "", *, known_ip: bool = False) -> bool:
        """known_ip: the user has signed in from this address before. Then only the limit per
        address applies, so nobody can lock a user out by sending wrong passwords."""
        ts = time.monotonic()
        with self._lock:
            if self._count(f"ip:{ip}", ts) >= self.max_ip:
                return True
            return bool(username) and not known_ip and self._count(f"user:{username.lower()}", ts) >= self.max_user

    def failure(self, ip: str, username: str = "") -> None:
        ts = time.monotonic()
        with self._lock:
            self._fails[f"ip:{ip}"].append(ts)
            if username:
                self._fails[f"user:{username.lower()}"].append(ts)

    def success(self, ip: str, username: str) -> None:
        with self._lock:
            self._fails.pop(f"user:{username.lower()}", None)


def log_login(conn: sqlite3.Connection, username: str, user_id: int | None, ip: str, success: bool,
              detail: str = "") -> None:
    conn.execute("INSERT INTO login_events (username, user_id, ip, success, detail, created_at)"
                 " VALUES (?, ?, ?, ?, ?, ?)",
                 (username[:USERNAME_MAX], user_id, ip, int(success), detail[:200], now()))


def known_login_ip(conn: sqlite3.Connection, username: str, ip: str) -> bool:
    if not username or not ip:
        return False
    return conn.execute("SELECT 1 FROM login_events WHERE success = 1 AND ip = ? AND username = ? COLLATE NOCASE"
                        " LIMIT 1", (ip, username)).fetchone() is not None


# ---------------------------------------------------------------- second step and recovery codes

def start_pending_login(conn: sqlite3.Connection, user_id: int) -> str:
    """Password was right, the second factor is missing: a short-lived secret for step two."""
    secret = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO pending_logins (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                 (token_hash(secret), user_id, now() + PENDING_SECONDS))
    return secret


def resolve_pending_login(conn: sqlite3.Connection, secret: str, count_attempt: bool = True) -> sqlite3.Row | None:
    if not secret:
        return None
    row = conn.execute(
        "SELECT p.id AS p_id, p.attempts AS p_attempts, p.expires_at AS p_expires_at, u.*"
        " FROM pending_logins p JOIN users u ON u.id = p.user_id WHERE p.token_hash = ?",
        (token_hash(secret),)).fetchone()
    if row is None:
        return None
    if row["p_expires_at"] < now() or row["p_attempts"] >= PENDING_MAX_ATTEMPTS:
        conn.execute("DELETE FROM pending_logins WHERE id = ?", (row["p_id"],))
        return None
    if count_attempt:
        conn.execute("UPDATE pending_logins SET attempts = attempts + 1 WHERE id = ?", (row["p_id"],))
    return row if row["enabled"] else None


def finish_pending_login(conn: sqlite3.Connection, pending_id: int) -> None:
    conn.execute("DELETE FROM pending_logins WHERE id = ?", (pending_id,))


def _normalize_recovery(code: str) -> str:
    return "".join(code.upper().split()).replace("-", "")


def new_recovery_codes(conn: sqlite3.Connection, user_id: int) -> list[str]:
    """Replaces all recovery codes and returns the new ones in plain text (shown once)."""
    conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
    codes = []
    for _ in range(RECOVERY_CODES):
        code = "-".join("".join(secrets.choice(_ALPHABET) for _ in range(4)) for _ in range(2))
        codes.append(code)
        conn.execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
                     (user_id, token_hash(_normalize_recovery(code))))
    return codes


def use_recovery_code(conn: sqlite3.Connection, user_id: int, code: str) -> bool:
    cur = conn.execute("UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
                       (now(), user_id, token_hash(_normalize_recovery(code))))
    return cur.rowcount == 1


def unused_recovery_codes(conn: sqlite3.Connection, user_id: int) -> int:
    return conn.execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
                        (user_id,)).fetchone()[0]


def has_passkeys(conn: sqlite3.Connection, user_id: int) -> bool:
    return conn.execute("SELECT 1 FROM passkeys WHERE user_id = ? LIMIT 1", (user_id,)).fetchone() is not None


def second_factor_required(conn: sqlite3.Connection, user: sqlite3.Row) -> bool:
    """After the password: a code from the app or a passkey."""
    return bool(user["totp_enabled"]) or has_passkeys(conn, user["id"])


def disable_totp(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("UPDATE users SET totp_secret = '', totp_enabled = 0, totp_last_step = 0 WHERE id = ?", (user_id,))
    if not has_passkeys(conn, user_id):   # recovery codes stay while passkeys are a second factor
        conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM pending_logins WHERE user_id = ?", (user_id,))


def reset_second_factors(conn: sqlite3.Connection, user_id: int) -> None:
    """For admins: remove code, passkeys and recovery codes of a user."""
    conn.execute("DELETE FROM passkeys WHERE user_id = ?", (user_id,))
    disable_totp(conn, user_id)
