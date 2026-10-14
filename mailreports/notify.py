# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Notifications (Pushover, ntfy, webhook, email) for new failures and unknown senders.

Each finding has a key (e.g. domain + IP). A key is reported at most once per
NOTIFY_COOLDOWN_HOURS, so a sender that shows up in every daily report does not
cause a message every day.
"""
from __future__ import annotations

import email.utils
import json
import logging
import smtplib
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage

from . import i18n
from .config import Settings
from .db import Database
from .explain import origin
from .i18n import _
from .sources import Source, classify

log = logging.getLogger(__name__)

PUSHOVER_URL = "https://api.pushover.net/1/messages.json"


@dataclass
class Finding:
    key: str
    line: str
    severity: int     # 2 = failure, 1 = unknown sender / TLS problem


def findings(db: Database, sources: list[Source], dmarc_ids: list[int], tls_ids: list[int]) -> list[Finding]:
    out: dict[str, Finding] = {}
    counts: dict[str, int] = {}
    if dmarc_ids:
        marks = ",".join("?" * len(dmarc_ids))
        with db.connect() as con:
            rows = con.execute(
                f"""SELECT r.*, p.domain, p.org_name FROM dmarc_records r
                    JOIN dmarc_reports p ON p.id = r.report_id WHERE p.id IN ({marks})""",
                dmarc_ids).fetchall()
        info = db.ip_info(sorted({r["source_ip"] for r in rows}))
        for r in rows:
            ip = r["source_ip"]
            verdict = classify(sources, r, info.get(ip))
            inf = info.get(ip)
            host = (inf["ptr"] if inf and inf["ptr"] else ip)
            where = origin(inf)
            where = f" ({where})" if where else ""
            if not r["dmarc_pass"] and verdict.kind != "forwarder":
                key = f"fail:{r['domain']}:{ip}"
                counts[key] = n = counts.get(key, 0) + r["count"]
                name = verdict.source.name if verdict.source else host
                out[key] = Finding(key, f"{n}× {r['domain']}: {_('DMARC fehlgeschlagen')} – {name}{where}, "
                                        f"{r['disposition']} ({r['org_name']})", 2)
            elif verdict.kind == "unknown" and r["dmarc_pass"]:
                key = f"unknown:{r['domain']}:{ip}"
                if key not in out:
                    out[key] = Finding(key, f"{r['domain']}: {_('unbekannter Absender mit gültiger Prüfung')} – "
                                            f"{host}{where}", 1)
    if tls_ids:
        marks = ",".join("?" * len(tls_ids))
        with db.connect() as con:
            rows = con.execute(
                f"""SELECT p.policy_domain, f.result_type, SUM(f.failed_session_count) AS n, t.org_name
                    FROM tls_failures f JOIN tls_policies p ON p.id = f.policy_id
                    JOIN tls_reports t ON t.id = p.report_id
                    WHERE t.id IN ({marks}) GROUP BY p.policy_domain, f.result_type, t.org_name""",
                tls_ids).fetchall()
        for r in rows:
            key = f"tls:{r['policy_domain']}:{r['result_type']}"
            if key not in out:
                out[key] = Finding(key, f"{r['n']}× {r['policy_domain']}: TLS {r['result_type']} ({r['org_name']})", 1)
    return list(out.values())


def send_pushover(settings: Settings, title: str, message: str, priority: int = 0) -> None:
    fields = {"token": settings.pushover_token, "user": settings.pushover_user,
              "title": title[:250], "message": message[:1024], "priority": str(priority)}
    if settings.base_url:
        fields["url"] = settings.base_url + "/"
        fields["url_title"] = _("Berichte öffnen")
    req = urllib.request.Request(PUSHOVER_URL, data=urllib.parse.urlencode(fields).encode(), method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:
        body = json.loads(resp.read() or b"{}")
    if body.get("status") != 1:
        raise RuntimeError(f"Pushover: {body.get('errors') or body}")


def send_ntfy(settings: Settings, title: str, message: str) -> None:
    """NTFY_URL is the topic address, e.g. https://ntfy.sh/my-topic (published as JSON to the server)."""
    server, _sep, topic = settings.ntfy_url.rpartition("/")
    body = {"topic": topic, "title": title[:250], "message": message[:4000], "tags": ["email"]}
    if settings.base_url:
        body["click"] = settings.base_url + "/"
    headers = {"Content-Type": "application/json"}
    if settings.ntfy_token:
        headers["Authorization"] = f"Bearer {settings.ntfy_token}"
    req = urllib.request.Request(server, data=json.dumps(body).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=20):  # noqa: S310 - address from the configuration
        pass


def send_webhook(settings: Settings, title: str, message: str, data: dict | None = None) -> None:
    body = {"title": title, "message": message, "url": settings.base_url + "/" if settings.base_url else "",
            **(data or {})}
    req = urllib.request.Request(settings.webhook_url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": "mailreports"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=20):  # noqa: S310 - address from the configuration
        pass


def send_email(settings: Settings, title: str, message: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(settings.notify_email)
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain=settings.smtp_from.rpartition("@")[2] or None)
    text = message + (f"\n\n{settings.base_url}/" if settings.base_url else "")
    msg.set_content(text)
    ctx = ssl.create_default_context()
    if settings.smtp_security == "ssl":
        server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, context=ctx, timeout=30)
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30)
        if settings.smtp_security == "starttls":
            server.starttls(context=ctx)
    try:
        if settings.smtp_user:
            server.login(settings.smtp_user, settings.smtp_password)
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except smtplib.SMTPException:
            pass


def channels(settings: Settings, title: str, message: str, data: dict | None = None) -> list:
    """(name, send) for every configured channel."""
    out = []
    if settings.pushover_enabled:
        out.append(("Pushover", lambda: send_pushover(settings, title, message)))
    if settings.ntfy_url:
        out.append(("ntfy", lambda: send_ntfy(settings, title, message)))
    if settings.webhook_url:
        out.append(("Webhook", lambda: send_webhook(settings, title, message, data)))
    if settings.email_enabled:
        out.append(("E-Mail", lambda: send_email(settings, title, message)))
    return out


def send_each(settings: Settings, title: str, message: str, data: dict | None = None) -> list[tuple[str, str]]:
    """Sends to every channel; (name, error) per channel, error empty on success."""
    results = []
    for name, send in channels(settings, title, message, data):
        try:
            send()
            results.append((name, ""))
        except (OSError, RuntimeError, ValueError, smtplib.SMTPException) as exc:
            log.warning("notification via %s failed: %s", name, exc)
            results.append((name, str(exc)[:300] or type(exc).__name__))
    return results


def send_all(db: Database, settings: Settings, title: str, message: str, data: dict | None = None) -> bool:
    """Sends to every configured channel. True if at least one succeeded; errors are kept for the status page."""
    results = send_each(settings, title, message, data)
    db.set_meta("last_notify_error", "; ".join(f"{name}: {err}" for name, err in results if err))
    return any(not err for _name, err in results)


def send_test(db: Database, settings: Settings) -> list[tuple[str, str]]:
    title = (settings.app_title or "mailreports") + ": " + _("Testnachricht")
    results = send_each(settings, title, _("Die Benachrichtigungen sind richtig eingerichtet."), {"test": True})
    db.set_meta("last_notify_error", "; ".join(f"{name}: {err}" for name, err in results if err))
    return results


def notify(db: Database, settings: Settings, sources: list[Source],
           dmarc_ids: list[int], tls_ids: list[int]) -> int:
    """Send one message with all new findings outside their cooldown. Returns the number reported."""
    if not settings.notify_enabled:
        return 0
    i18n.set_language(settings.default_language or i18n.DEFAULT)
    cooldown = settings.notify_cooldown_hours * 3600
    fresh = [f for f in findings(db, sources, dmarc_ids, tls_ids) if not db.notified_recently(f.key, cooldown)]
    if not fresh:
        return 0
    fresh.sort(key=lambda f: -f.severity)
    lines = [f.line for f in fresh[:10]]
    if len(fresh) > 10:
        lines.append(_("… und {n} weitere", n=len(fresh) - 10))
    title = settings.app_title or "mailreports"
    title += ": " + (_("DMARC-Fehlschläge") if fresh[0].severity == 2 else _("Auffälligkeiten"))
    if not send_all(db, settings, title, "\n".join(lines), {"findings": [f.line for f in fresh]}):
        return 0
    db.mark_notified([f.key for f in fresh])
    return len(fresh)


def weekly_digest(db: Database, settings: Settings, sources: list[Source], tz) -> str:
    """Text of the weekly summary (last 7 days)."""
    from . import queries
    i18n.set_language(settings.default_language or i18n.DEFAULT)
    lines = [_("Zusammenfassung der letzten 7 Tage"), ""]
    summaries = queries.domain_summaries(db, 7, tz, settings.domains or None)
    if not summaries:
        lines.append(_("Keine Berichte eingegangen."))
    for s in summaries:
        rate = f"{s.rate:.1f} %" if s.rate is not None else "–"
        lines.append(_("{domain}: {n} E-Mails, DMARC bestanden {rate}, nicht bestanden {failed}",
                       domain=s.domain, n=s.messages, rate=rate, failed=s.failed))
        if s.tls_success or s.tls_failure:
            lines.append("  " + _("TLS: {ok} erfolgreich, {bad} fehlgeschlagen", ok=s.tls_success, bad=s.tls_failure))
    unknown = [r for r in queries.sources_for(db, sources, 7) if r.kind == "unknown"]
    if unknown:
        lines += ["", _("Unbekannte Absender: {n}", n=len(unknown))]
        for r in unknown[:5]:
            lines.append(f"  {r.ip} ({r.messages}) {r.info['ptr'] if r.info and r.info['ptr'] else ''}".rstrip())
    return "\n".join(lines)


def send_digest(db: Database, settings: Settings, sources: list[Source], tz) -> bool:
    title = (settings.app_title or "mailreports") + ": " + _("Wochenübersicht")
    return send_all(db, settings, title, weekly_digest(db, settings, sources, tz), {"digest": True})
