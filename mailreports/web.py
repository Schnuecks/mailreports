# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Templates and formatting helpers."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from . import __version__, explain, i18n

TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def fmt_number(value) -> str:
    if value is None:
        return "–"
    text = f"{int(value):,}"
    return text.replace(",", ".") if i18n.current() == "de" else text


def fmt_pct(value) -> str:
    if value is None:
        return "–"
    text = "100" if value >= 99.95 else f"{value:.1f}"
    return (text.replace(".", ",") if i18n.current() == "de" else text) + " %"


class Formatter:
    def __init__(self, tz: ZoneInfo):
        self.tz = tz

    def date(self, ts) -> str:
        if not ts:
            return "–"
        dt = datetime.fromtimestamp(int(ts), self.tz)
        return dt.strftime("%d.%m.%Y") if i18n.current() == "de" else dt.strftime("%Y-%m-%d")

    def datetime(self, ts) -> str:
        if not ts:
            return "–"
        dt = datetime.fromtimestamp(int(ts), self.tz)
        return dt.strftime("%d.%m.%Y %H:%M") if i18n.current() == "de" else dt.strftime("%Y-%m-%d %H:%M")

    def day(self, d) -> str:
        return d.strftime("%d.%m.") if i18n.current() == "de" else d.strftime("%m-%d")

    def range(self, begin, end) -> str:
        if not begin:
            return "–"
        if end and int(end) - int(begin) <= 86400:
            return self.date((int(begin) + int(end)) // 2)   # a daily report: show its day
        a, b = self.date(begin), self.date(end)
        return a if a == b or not end else f"{a} – {b}"


def bar_chart(daily, fmt: Formatter, height: int = 120, label: str = "") -> Markup:
    """Stacked daily bars (passed below, failed on top) with a tooltip per day."""
    if not daily:
        return Markup("")
    peak = max((ok + bad for _, ok, bad in daily), default=0) or 1
    step = 12
    width = step * len(daily)
    bars = []
    for i, (d, ok, bad) in enumerate(daily):
        x = i * step + 1.5
        w = step - 3
        h_ok = ok / peak * (height - 4)
        h_bad = bad / peak * (height - 4)
        gap = 1.5 if ok and bad else 0
        tip = i18n._("{day}: {ok} bestanden, {bad} durchgefallen",
                     day=fmt.day(d), ok=fmt_number(ok), bad=fmt_number(bad))
        parts = [f'<rect class="hit" x="{i * step}" y="0" width="{step}" height="{height}"/>']
        if ok:
            parts.append(f'<rect class="ok" x="{x}" y="{height - h_ok:.2f}" width="{w}" height="{h_ok:.2f}"/>')
        if bad:
            y = height - h_ok - gap - h_bad
            parts.append(f'<rect class="bad" x="{x}" y="{max(0, y):.2f}" width="{w}" height="{h_bad:.2f}"/>')
        bars.append(f'<g><title>{escape(tip)}</title>{"".join(parts)}</g>')
    aria = escape(label or i18n._("Mails pro Tag"))
    return Markup(
        f'<svg class="bars" viewBox="0 0 {width} {height}" preserveAspectRatio="none" role="img" '
        f'aria-label="{aria}" width="100%" height="{height}">'
        f'<line class="base" x1="0" y1="{height - 0.5}" x2="{width}" y2="{height - 0.5}"/>'
        + "".join(bars) + "</svg>")


def loads(value) -> list:
    try:
        return json.loads(value or "[]")
    except (TypeError, ValueError):
        return []


def setup(service) -> None:
    s = service.settings
    tz = zone(s.timezone)
    fmt = Formatter(tz)
    env = templates.env
    env.globals.update(
        _=i18n.gettext, ngettext=i18n.ngettext, fmt=fmt, num=fmt_number, pct=fmt_pct,
        bar_chart=bar_chart, loads=loads, ex=explain, version=__version__,
        app_title=s.app_title, logo_url=s.logo_url, languages=i18n.LANGUAGES,
        current_language=i18n.current,
    )
    service.tz = tz
    service.fmt = fmt
