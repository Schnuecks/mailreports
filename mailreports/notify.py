# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Push notifications (Pushover) for new failures and unknown senders.

Each finding has a key (e.g. domain + IP). A key is reported at most once per
NOTIFY_COOLDOWN_HOURS, so a sender that shows up in every daily report does not
cause a message every day.
"""
from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
from dataclasses import dataclass

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


def notify(db: Database, settings: Settings, sources: list[Source],
           dmarc_ids: list[int], tls_ids: list[int]) -> int:
    """Send one message with all new findings outside their cooldown. Returns the number reported."""
    if not settings.pushover_enabled:
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
    try:
        send_pushover(settings, title, "\n".join(lines))
    except (OSError, RuntimeError, ValueError) as exc:
        log.warning("notification failed: %s", exc)
        db.set_meta("last_notify_error", str(exc)[:500])
        return 0
    db.mark_notified([f.key for f in fresh])
    db.set_meta("last_notify_error", "")
    return len(fresh)
