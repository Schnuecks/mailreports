# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Translations.

The German texts in the code are also the keys. mailreports/locales/<code>.json
maps them to the translation; if an entry is missing, the German text remains.
Placeholders are in curly braces: _("{n} E-Mails", n=3).

The language applies per request: cookie "lang", otherwise DEFAULT_LANGUAGE,
otherwise the browser language, otherwise English.
"""
from __future__ import annotations

import contextvars
import json
from pathlib import Path

LANGUAGES = {"de": "Deutsch", "en": "English", "fr": "Français", "es": "Español", "it": "Italiano",
             "nl": "Nederlands"}
FALLBACK = "de"   # language of the texts in the code
DEFAULT = "en"    # if the browser language is not supported

LOCALE_DIR = Path(__file__).parent / "locales"
_catalogs: dict[str, dict[str, str]] = {}
_lang: contextvars.ContextVar[str] = contextvars.ContextVar("lang", default=FALLBACK)


def catalog(lang: str) -> dict[str, str]:
    if lang not in _catalogs:
        path = LOCALE_DIR / f"{lang}.json"
        _catalogs[lang] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    return _catalogs[lang]


def set_language(lang: str) -> None:
    _lang.set(lang if lang in LANGUAGES else FALLBACK)


def current() -> str:
    return _lang.get()


def gettext(msg: str, **kwargs) -> str:
    lang = current()
    text = msg if lang == FALLBACK else catalog(lang).get(msg) or msg
    return text.format(**kwargs) if kwargs else text


def ngettext(singular: str, plural: str, n: int, **kwargs) -> str:
    return gettext(singular if n == 1 else plural, n=n, **kwargs)


def pick_language(cookie: str | None, default: str | None, accept: str | None) -> str:
    if cookie in LANGUAGES:
        return cookie
    if default in LANGUAGES:
        return default
    for part in (accept or "").split(","):
        code = part.split(";")[0].strip().lower()[:2]
        if code in LANGUAGES:
            return code
    return DEFAULT


_ = gettext


def N_(msg: str) -> str:
    """Marks a text for translation without translating it yet (constants)."""
    return msg
