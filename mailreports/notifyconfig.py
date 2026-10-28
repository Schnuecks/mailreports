# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Notification settings changed on the settings page.

They are stored as JSON in the meta table; tokens and passwords are encrypted with
SECRET_KEY (see secretbox). A variable set in the environment always wins: such a field
is shown as fixed and cannot be changed in the app.
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass

from . import secretbox
from .config import NOTIFY_VARS, WEEKDAYS, Settings
from .db import Database
from .i18n import N_

META_KEY = "notify_settings"
SECRETS = {"pushover_token", "pushover_user", "ntfy_token", "webhook_url", "smtp_password"}
INTS = {"smtp_port": (1, 65535), "digest_weekday": (0, 6), "notify_cooldown_hours": (1, 24 * 30)}
CHOICES = {"smtp_security": ("starttls", "ssl", "none"), "digest": ("off", "weekly"),
           "dns_watch": ("on", "off")}
URLS = {"ntfy_url", "webhook_url"}
CHANNEL_OF = {"pushover_token": "Pushover", "pushover_user": "Pushover", "ntfy_token": "ntfy",
              "webhook_url": "Webhook", "smtp_password": "E-Mail"}


class Invalid(ValueError):
    """German message (translation key) and the field it belongs to."""

    def __init__(self, message: str, field: str, **params):
        super().__init__(message)
        self.message, self.field, self.params = message, field, params


@dataclass
class Stored:
    values: dict          # plain values of the fields saved in the app
    unreadable: list      # encrypted fields that cannot be decrypted (SECRET_KEY missing or changed)


def load(db: Database, secret_key: str) -> Stored:
    try:
        raw = json.loads(db.get_meta(META_KEY) or "{}")
    except ValueError:
        raw = {}
    values, unreadable = {}, []
    for name, value in raw.items():
        if name not in NOTIFY_VARS:
            continue
        if name in SECRETS and isinstance(value, str):
            plain = secretbox.open_(secret_key, value)
            if value and not plain:
                unreadable.append(name)
                continue
            value = plain
        values[name] = value
    return Stored(values, unreadable)


def effective(base: Settings, db: Database) -> Settings:
    """Settings with the values from the settings page; the environment takes precedence."""
    stored = load(db, base.secret_key).values
    changes = {k: v for k, v in stored.items() if k not in base.env_given}
    return dataclasses.replace(base, **changes) if changes else base


def _clean(name: str, value: str):
    value = value.strip()
    if name in INTS:
        low, high = INTS[name]
        if name == "digest_weekday" and value in WEEKDAYS:
            return WEEKDAYS.index(value)
        try:
            number = int(value)
        except ValueError:
            raise Invalid(N_("Bitte eine ganze Zahl zwischen {low} und {high} eingeben."), name,
                          low=low, high=high) from None
        if not low <= number <= high:
            raise Invalid(N_("Bitte eine ganze Zahl zwischen {low} und {high} eingeben."), name, low=low, high=high)
        return number
    if name in CHOICES:
        if value not in CHOICES[name]:
            raise Invalid(N_("Ungültige Auswahl."), name)
        return value
    if name == "notify_email":
        addresses = [a.strip() for a in value.replace(";", ",").replace("\n", ",").split(",") if a.strip()]
        for a in addresses:
            if "@" not in a or " " in a:
                raise Invalid(N_("{value} ist keine gültige E-Mail-Adresse."), name, value=a)
        return addresses
    if name in URLS and value:
        if not value.startswith(("https://", "http://")) or " " in value:
            raise Invalid(N_("Die Adresse muss mit https:// oder http:// beginnen."), name)
        return value.rstrip("/") if name == "ntfy_url" else value
    if name == "smtp_from" and value and "@" not in value:
        raise Invalid(N_("{value} ist keine gültige E-Mail-Adresse."), name, value=value)
    return value


def save(db: Database, base: Settings, form: dict[str, str], clear: set[str]) -> None:
    """Store the submitted fields. An empty secret field keeps the stored value, unless it is in clear."""
    try:
        raw = json.loads(db.get_meta(META_KEY) or "{}")
    except ValueError:
        raw = {}
    out = {}
    for name in NOTIFY_VARS:
        if name in base.env_given:
            continue
        if name in SECRETS:
            given = form.get(name, "").strip()
            if name in clear:
                continue
            if given:
                out[name] = secretbox.seal(base.secret_key, _clean(name, given))
            elif raw.get(name):
                out[name] = raw[name]
            continue
        if name not in form:
            if name in raw:
                out[name] = raw[name]
            continue
        value = form[name]
        if name == "smtp_port" and not value.strip():
            value = "465" if form.get("smtp_security") == "ssl" else "587"
        out[name] = _clean(name, value)
    db.set_meta(META_KEY, json.dumps(out, ensure_ascii=False))
