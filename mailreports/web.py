# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Templates and formatting helpers."""
from __future__ import annotations

import ipaddress
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
    if value >= 99.95 or value <= 0:
        text = str(round(value))
    else:
        text = f"{value:.1f}"
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
        return d.strftime("%d.%m.") if i18n.current() == "de" else f"{d:%b} {d.day}"

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
        tip = i18n._("{day}: {ok} bestanden, {bad} nicht bestanden",
                     day=fmt.day(d), ok=fmt_number(ok), bad=fmt_number(bad))
        parts = [f'<rect class="hit" x="{i * step}" y="0" width="{step}" height="{height}"/>']
        if ok:
            parts.append(f'<rect class="ok" x="{x}" y="{height - h_ok:.2f}" width="{w}" height="{h_ok:.2f}"/>')
        if bad:
            y = height - h_ok - gap - h_bad
            parts.append(f'<rect class="bad" x="{x}" y="{max(0, y):.2f}" width="{w}" height="{h_bad:.2f}"/>')
        bars.append(f'<g><title>{escape(tip)}</title>{"".join(parts)}</g>')
    aria = escape(label or i18n._("E-Mails pro Tag"))
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
        app_title=s.app_title, theme=s.theme,
        logo_url=s.logo_url or ("/static/icon-olive.svg" if s.theme == "olive" else "/static/icon.svg"),
        source_url=s.source_url, languages=i18n.LANGUAGES,
        current_language=i18n.current,
    )
    service.tz = tz
    service.fmt = fmt


# ---------------------------------------------------------------- request helpers

PERIODS = (7, 30, 90, 365)
COOKIE = "mailreports_session"


def peer_ip(request) -> str:
    """Address of the direct peer, i.e. the reverse proxy if there is one."""
    return request.client.host if request.client else ""


def _trusted(addr: str, networks) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in networks)


def client_ip(request) -> str:
    """Address of the visitor. Behind a proxy from TRUSTED_PROXIES the rightmost address in
    X-Forwarded-For that is not a trusted proxy; otherwise the peer itself (the header can be
    forged by anybody who reaches the port directly)."""
    peer = peer_ip(request)
    networks = request.app.state.svc.settings.trusted_proxies
    forwarded = request.headers.get("x-forwarded-for", "")
    if not networks or not forwarded or not _trusted(peer, networks):
        return peer
    for part in reversed([p.strip() for p in forwarded.split(",") if p.strip()]):
        try:
            addr = str(ipaddress.ip_address(part))
        except ValueError:
            return peer
        if not _trusted(addr, networks):
            return addr
    return peer


def cookie_secure(request, settings) -> bool:
    if settings.cookie_secure is not None:
        return settings.cookie_secure
    return request.url.scheme == "https" or settings.public_url.startswith("https://")


def session_cookie(request, settings) -> str:
    """Over HTTPS with the __Host- prefix: the browser then accepts the cookie only from
    exactly this address, only over HTTPS and for all paths."""
    return f"__Host-{COOKIE}" if cookie_secure(request, settings) else COOKIE


def days_of(request) -> int:
    try:
        days = int(request.query_params.get("days", "30"))
    except ValueError:
        days = 30
    return days if days in PERIODS else 30


def page_of(request) -> int:
    try:
        return max(1, int(request.query_params.get("page", "1")))
    except ValueError:
        return 1


def safe_next(value: str) -> str:
    """Only local paths, so a link cannot redirect elsewhere after signing in."""
    return value if value.startswith("/") and not value.startswith("//") and "\\" not in value else "/"


def account(request):
    return getattr(request.state, "account", None)


def is_admin(request) -> bool:
    return getattr(request.state, "is_admin", False)


def check_csrf(request, token: str) -> bool:
    """Form token of the session (built-in accounts); behind a proxy the same-origin check applies."""
    acc = account(request)
    if acc is None:
        return not request.app.state.svc.settings.accounts_enabled
    import secrets
    return bool(token) and secrets.compare_digest(acc["s_csrf"], token)


def public_url_problem(request) -> str:
    """German hint if PUBLIC_URL is missing or does not match the address in the browser."""
    from urllib.parse import urlsplit
    s = request.app.state.svc.settings
    if not s.accounts_enabled:
        return ""
    host = request.headers.get("host", "")
    if not s.public_url:
        return i18n.N_("PUBLIC_URL ist nicht gesetzt. Hinter einem Reverse-Proxy funktionieren Passkeys und "
                       "Single Sign-on erst damit, z. B. PUBLIC_URL=https://{host}.")
    if host and urlsplit(s.public_url).netloc.lower() != host.lower():
        return i18n.N_("PUBLIC_URL ({public}) passt nicht zur aufgerufenen Adresse ({host}). Passkeys und "
                       "Single Sign-on funktionieren nur unter der Adresse aus PUBLIC_URL.")
    return ""


def render(request, name: str, status: int = 200, **ctx):
    svc = request.app.state.svc
    s = svc.settings
    acc = account(request)
    ctx.setdefault("days", days_of(request))
    ctx.setdefault("error", "")
    ctx.update(request=request, periods=PERIODS, nav=name.split(".")[0], fetch_running=svc.running,
               user=getattr(request.state, "user", ""), account=acc, is_admin=is_admin(request),
               csrf=acc["s_csrf"] if acc is not None else "", accounts_enabled=s.accounts_enabled,
               sso_name=s.oidc_name if s.oidc_enabled else "",
               public_url_hint=public_url_problem(request) if name in ("status.html", "account.html") else "",
               public_url=s.public_url, request_host=request.headers.get("host", ""))
    return templates.TemplateResponse(request, name, ctx, status_code=status)
