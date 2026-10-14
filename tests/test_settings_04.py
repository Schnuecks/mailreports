# SPDX-License-Identifier: AGPL-3.0-or-later
"""0.4.0: notification settings in the app."""
import json

import pytest
from fastapi.testclient import TestClient

from mailreports import notify, notifyconfig
from mailreports.main import create_app
from mailreports.service import Service
from tests.conftest import make_settings
from tests.test_accounts import ADMIN_PW, app_client, csrf_of, login

DE = {"accept-language": "de"}
FORM = {"pushover_token": "", "pushover_user": "", "ntfy_url": "", "ntfy_token": "", "webhook_url": "",
        "smtp_host": "", "smtp_port": "", "smtp_security": "starttls", "smtp_user": "", "smtp_password": "",
        "smtp_from": "", "notify_email": "", "digest": "off", "digest_weekday": "0", "notify_cooldown_hours": "24"}


def make(tmp_path, **kw):
    svc = Service(make_settings(tmp_path, secret_key="k" * 32, **kw))
    return TestClient(create_app(svc), headers=DE), svc


def test_save_and_use(tmp_path):
    c, svc = make(tmp_path)
    assert "Einstellungen" in c.get("/").text
    r = c.post("/settings", data={**FORM, "pushover_token": "tok-123", "pushover_user": "usr-456",
                                  "ntfy_url": "https://ntfy.example.org/topic/", "digest": "weekly",
                                  "digest_weekday": "4", "notify_cooldown_hours": "6"}, follow_redirects=False)
    assert r.status_code == 303
    raw = json.loads(svc.db.get_meta(notifyconfig.META_KEY))
    assert raw["pushover_token"].startswith("enc:v1:") and "tok-123" not in json.dumps(raw)
    s = svc.notify_settings()
    assert s.pushover_enabled and s.pushover_token == "tok-123"
    assert s.ntfy_url == "https://ntfy.example.org/topic"
    assert (s.digest, s.digest_weekday, s.notify_cooldown_hours) == ("weekly", 4, 6)
    page = c.get("/settings").text
    assert "tok-123" not in page and "gespeichert – leer lassen" in page
    # empty secret keeps the value, "entfernen" deletes it
    c.post("/settings", data={**FORM, "notify_cooldown_hours": "12"})
    assert svc.notify_settings().pushover_token == "tok-123"
    c.post("/settings", data={**FORM, "clear_pushover_token": "1"})
    assert svc.notify_settings().pushover_token == "" and svc.notify_settings().pushover_user == "usr-456"
    assert "Pushover" not in c.get("/status").text.split("Benachrichtigungen")[1][:200]


def test_environment_wins(tmp_path):
    c, svc = make(tmp_path, pushover_token="env-token", env_given=frozenset({"pushover_token"}))
    c.post("/settings", data={**FORM, "pushover_token": "app-token", "pushover_user": "u"})
    assert svc.notify_settings().pushover_token == "env-token"
    assert "app-token" not in svc.db.get_meta(notifyconfig.META_KEY)
    assert "Festgelegt über PUSHOVER_TOKEN" in c.get("/settings").text


@pytest.mark.parametrize("field,value", [("ntfy_url", "ftp://x"), ("notify_email", "kein-at"),
                                         ("smtp_port", "99999"), ("notify_cooldown_hours", "0"),
                                         ("smtp_security", "tls13")])
def test_invalid_values(tmp_path, field, value):
    c, svc = make(tmp_path)
    r = c.post("/settings", data={**FORM, field: value})
    assert r.status_code == 400 and 'aria-invalid="true"' in r.text
    assert not svc.db.get_meta(notifyconfig.META_KEY)


def test_smtp_port_default(tmp_path):
    c, svc = make(tmp_path)
    c.post("/settings", data={**FORM, "smtp_host": "smtp.example.org", "smtp_security": "ssl",
                              "smtp_from": "a@example.org", "notify_email": "b@example.org; c@example.org"})
    s = svc.notify_settings()
    assert s.smtp_port == 465 and s.notify_email == ["b@example.org", "c@example.org"] and s.email_enabled


def test_test_message(tmp_path, monkeypatch):
    c, svc = make(tmp_path)
    r = c.post("/settings", data={**FORM, "action": "test"})
    assert "noch kein Kanal" in r.text
    sent = []
    monkeypatch.setattr(notify, "send_pushover", lambda s, title, msg, priority=0: sent.append((s.pushover_token, msg)))

    def broken(s, title, msg):
        raise OSError("connection refused")
    monkeypatch.setattr(notify, "send_ntfy", broken)
    r = c.post("/settings", data={**FORM, "pushover_token": "t", "pushover_user": "u",
                                  "ntfy_url": "https://ntfy.example.org/x", "action": "test"})
    assert sent and sent[0][0] == "t"
    assert "zugestellt" in r.text and "connection refused" in r.text
    assert "ntfy: connection refused" in svc.db.get_meta("last_notify_error")


def test_wrong_secret_key(tmp_path):
    c, svc = make(tmp_path)
    c.post("/settings", data={**FORM, "pushover_token": "t", "pushover_user": "u"})
    svc.settings.secret_key = "other" * 8
    assert not svc.notify_settings().pushover_enabled
    assert "nicht entschlüsseln" in c.get("/settings").text


def test_admins_only(tmp_path):
    client, svc = app_client(tmp_path, admin_password=ADMIN_PW, secret_key="k" * 32)
    login(client, "admin", ADMIN_PW)
    csrf = csrf_of(client)
    assert client.post("/settings", data=FORM, follow_redirects=False).status_code == 403   # no CSRF token
    assert client.post("/settings", data={**FORM, "csrf": csrf}, follow_redirects=False).status_code == 303
    with svc.db.connect() as con:
        from mailreports import accounts
        accounts.create_user(con, "reader", "reader-password-1", is_admin=False)
    reader = TestClient(create_app(svc), headers=DE)
    login(reader, "reader", "reader-password-1")
    assert reader.get("/settings").status_code == 403
    assert "/settings" not in reader.get("/").text
