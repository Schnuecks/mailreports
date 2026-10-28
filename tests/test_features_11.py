# SPDX-License-Identifier: AGPL-3.0-or-later
"""1.1.0: known senders in the app, daily DNS check, sender of the report mail, BIMI."""
import dataclasses
import json

import pytest
from fastapi.testclient import TestClient

from mailreports import accounts, dnscheck, dnswatch, notify
from mailreports import sources as known
from mailreports.ingest import ingest_mail, ingest_payload
from mailreports.main import create_app
from mailreports.parsing import Payload
from mailreports.sources import classify
from tests.conftest import DMARC_XML, TLS_JSON
from tests.test_accounts import ADMIN_PW, USER_PW, app_client, csrf_of, login
from tests.test_ingest import mail

DE = {"accept-language": "de"}


@pytest.fixture
def filled(service):
    ingest_payload(service.db, Payload("a.xml", DMARC_XML))
    return service


@pytest.fixture
def c(filled):
    with TestClient(create_app(filled), headers=DE) as client:
        yield client


# ---------------------------------------------------------------- known senders

def test_parse_form_checks_values():
    src = known.parse_form({"name": "Mailer", "kind": "relay", "ips": "198.51.100.0/24, 2001:db8::1",
                            "ptr": ".Mail.Example.NET.", "asn": "AS64500", "dkim_selectors": "s1 s2"})
    assert [str(n) for n in src.ips] == ["198.51.100.0/24", "2001:db8::1/128"]
    assert src.ptr == [".mail.example.net"] and src.asn == [64500] and src.dkim_selectors == ["s1", "s2"]
    cases = [({"name": "", "kind": "relay", "ips": "192.0.2.1"}, "name"),
             ({"name": "x", "kind": "evil", "ips": "192.0.2.1"}, "kind"),
             ({"name": "x", "kind": "own"}, "ips"),                                   # no criterion at all
             ({"name": "x", "kind": "own", "ips": "10.0.0.0/8"}, "ips"),              # far too wide
             ({"name": "x", "kind": "own", "ips": "2001:db8::/16"}, "ips"),
             ({"name": "x", "kind": "own", "ips": "300.1.1.1"}, "ips"),
             ({"name": "x", "kind": "own", "ptr": "localhost"}, "ptr"),
             ({"name": "x", "kind": "own", "asn": "ASX"}, "asn"),
             ({"name": "x", "kind": "own", "dkim_selectors": "a/b"}, "dkim_selectors"),
             ({"name": "x", "kind": "own", "dkim_selectors": "s1", "dkim_domains": ".x.org"}, "dkim_domains")]
    for form, field in cases:
        with pytest.raises(known.Invalid) as err:
            known.parse_form(form)
        assert err.value.field == field, form


def test_add_edit_delete_known_sender(c, filled):
    page = c.get("/sources/203.0.113.5")
    assert "Als bekannten Absender eintragen" in page.text
    form = c.get("/known-sources/new?ip=203.0.113.5")
    assert 'value="203.0.113.5"' in form.text
    r = c.post("/known-sources", data={"name": "Ticket system", "kind": "relay", "ips": "203.0.113.5",
                                       "from_ip": "203.0.113.5"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/sources/203.0.113.5?saved=1"
    with filled.db.connect() as con:
        rec = con.execute("SELECT * FROM dmarc_records WHERE source_ip = '203.0.113.5'").fetchone()
        sid = con.execute("SELECT id FROM known_sources").fetchone()[0]
    assert classify(filled.sources, rec, None).source.name == "Ticket system"
    listing = c.get("/sources").text
    assert "Ticket system" in listing and f"/known-sources/{sid}" in listing and "sources.toml" in listing

    bad = c.post(f"/known-sources/{sid}", data={"name": "Ticket system", "kind": "relay", "ips": "0.0.0.0/0"})
    assert bad.status_code == 400 and "zu groß" in bad.text
    c.post(f"/known-sources/{sid}", data={"name": "Helpdesk", "kind": "own", "ips": "203.0.113.0/24"})
    assert classify(filled.sources, rec, None).source.name == "Helpdesk"

    assert c.post(f"/known-sources/{sid}/delete", follow_redirects=False).status_code == 303
    assert classify(filled.sources, rec, None).kind == "unknown"
    assert c.get(f"/known-sources/{sid}").status_code == 404
    assert c.post("/known-sources/999", data={"name": "x", "kind": "own", "ips": "192.0.2.1"}).status_code == 404


def test_known_senders_survive_restart(filled, tmp_path):
    with filled.db.connect() as con:
        known.save_source(con, known.parse_form({"name": "Stored", "kind": "own", "ips": "203.0.113.5"}))
    from mailreports.service import Service
    again = Service(filled.settings)
    assert [s.name for s in again.sources] == ["Own mail server", "Newsletter service", "Stored"]


def test_known_senders_only_for_admins(tmp_path):
    client, svc = app_client(tmp_path, admin_password=ADMIN_PW)
    with svc.db.connect() as con:
        accounts.create_user(con, "reader", USER_PW)
    login(client, "reader", USER_PW)
    assert client.get("/known-sources/new").status_code == 403
    token = csrf_of(client)
    assert client.post("/known-sources", data={"csrf": token, "name": "x", "kind": "own",
                                               "ips": "192.0.2.1"}).status_code == 403
    assert "/known-sources/new" not in client.get("/sources").text


def test_known_sender_needs_csrf(tmp_path):
    client, svc = app_client(tmp_path, admin_password=ADMIN_PW)
    login(client, "admin", ADMIN_PW)
    assert client.post("/known-sources", data={"name": "x", "kind": "own", "ips": "192.0.2.1"}).status_code == 403
    token = csrf_of(client)
    r = client.post("/known-sources", data={"csrf": token, "name": "x", "kind": "own", "ips": "192.0.2.1"},
                    follow_redirects=False)
    assert r.status_code == 303 and [s.name for s in svc.sources][-1] == "x"


# ---------------------------------------------------------------- sender of the report mail

def test_report_shows_sender_of_mail(service):
    out = ingest_mail(service.db, mail(("r.xml", DMARC_XML, "application/xml"), ("t.json", TLS_JSON,
                                                                                 "application/json")))
    with TestClient(create_app(service), headers=DE) as client:
        page = client.get(f"/reports/{out.new_dmarc[0]}")
        assert "Absender der E-Mail" in page.text and "noreply-dmarc-support@google.com" in page.text
        assert "noreply-dmarc-support@google.com" in client.get(f"/tls/{out.new_tls[0]}").text


def test_uploaded_report_has_no_mail_sender(c, filled):
    with filled.db.connect() as con:
        rid = con.execute("SELECT id FROM dmarc_reports").fetchone()[0]
    assert "Absender der E-Mail" not in c.get(f"/reports/{rid}").text


# ---------------------------------------------------------------- BIMI

@pytest.mark.parametrize(("record", "dmarc", "level", "text"), [
    (None, "v=DMARC1; p=reject", "info", "optional"),
    ("v=BIMI1; l=https://example.org/logo.svg; a=https://example.org/vmc.pem", "v=DMARC1; p=reject", "ok", "Logo"),
    ("v=BIMI1; l=https://example.org/logo.svg", "v=DMARC1; p=quarantine", "info", "Markenzertifikat"),
    ("v=BIMI1; l=http://example.org/logo.svg", "v=DMARC1; p=reject", "bad", "HTTPS"),
    ("v=BIMI1; l=https://example.org/logo.png", "v=DMARC1; p=reject", "warn", "SVG"),
    ("v=BIMI1; l=; a=", "v=DMARC1; p=reject", "info", "kein Logo"),
    ("v=BIMI1; l=https://example.org/logo.svg", "v=DMARC1; p=none", "warn", "p=quarantine"),
    ("v=BIMI1; l=https://example.org/logo.svg", "v=DMARC1; p=reject; pct=50", "warn", "pct=100"),
])
def test_bimi(monkeypatch, record, dmarc, level, text):
    monkeypatch.setattr(dnscheck, "txt", lambda name: [record] if record and name == "default._bimi.example.org"
                        else [])
    sec = dnscheck.check_bimi("example.org", dnscheck.Section("dmarc", "DMARC", record=dmarc))
    assert sec.level == level
    assert any(text in f.text.format(**f.args) for f in sec.findings)


# ---------------------------------------------------------------- daily DNS check

def sections(spf="v=spf1 mx -all", spf_level="ok", extra=None):
    dmarc = dnscheck.Section("dmarc", "DMARC", record="v=DMARC1; p=reject")
    dmarc.add("ok", "Richtlinie p=reject: E-Mails, die DMARC nicht bestehen, werden abgewiesen.")
    sec = dnscheck.Section("spf", "SPF", record=spf)
    sec.add(spf_level, "{n} DNS-Abfragen nötig; erlaubt sind höchstens 10, sonst schlägt SPF fehl.", n=12)
    out = [dmarc, sec]
    if extra:
        out.append(extra)
    return out


def test_snapshot_compare():
    old = dnswatch.snapshot(sections())
    assert dnswatch.compare("example.org", old, old) == []
    changes = dnswatch.compare("example.org", old, dnswatch.snapshot(sections("v=spf1 a -all", "bad")))
    assert [(c.section, c.kind) for c in changes] == [("spf", "problem"), ("spf", "record")]
    assert changes[1].old == "v=spf1 mx -all" and changes[1].new == "v=spf1 a -all"
    # only the number changed: not a new problem
    a = sections(spf_level="bad")
    b = sections(spf_level="bad")
    b[1].findings[0].args["n"] = 14
    assert dnswatch.compare("example.org", dnswatch.snapshot(a), dnswatch.snapshot(b)) == []
    resolved = dnswatch.compare("example.org", dnswatch.snapshot(a), dnswatch.snapshot(sections()))
    assert [c.kind for c in resolved] == ["resolved"]


def test_dns_watch_baseline_then_changes(filled, monkeypatch):
    current = {"spf": "v=spf1 mx -all"}
    monkeypatch.setattr(dnscheck, "check_domain",
                        lambda d, sel, mb, refresh=False: sections(current["spf"]))
    assert dnswatch.check(filled.db, filled.settings) == []            # first run only records the state
    current["spf"] = "v=spf1 mx include:new.example -all"
    changes = dnswatch.check(filled.db, filled.settings)
    assert [(c.domain, c.section, c.kind) for c in changes] == [("example.org", "spf", "record")]
    assert dnswatch.check(filled.db, filled.settings) == []            # nothing new the next day
    stored = dnswatch.recent(filled.db, "example.org")
    assert len(stored) == 1 and stored[0]["new"] == "v=spf1 mx include:new.example -all"


def test_dns_watch_skips_unreachable_dns(filled, monkeypatch):
    monkeypatch.setattr(dnscheck, "check_domain", lambda d, sel, mb, refresh=False: sections())
    dnswatch.check(filled.db, filled.settings)
    error = dnscheck.Section("error", "DNS")
    error.add("bad", "Die DNS-Abfrage ist fehlgeschlagen: {error}", error="timeout")
    monkeypatch.setattr(dnscheck, "check_domain", lambda d, sel, mb, refresh=False: [error])
    assert dnswatch.check(filled.db, filled.settings) == []
    assert json.loads(filled.db.get_meta("dns_snapshot:example.org"))["spf"]["record"] == "v=spf1 mx -all"


def test_dns_watch_message(filled, monkeypatch):
    sent = []
    monkeypatch.setattr(notify, "send_all", lambda db, s, title, message, data=None: sent.append((title, message,
                                                                                                  data)) or True)
    settings = dataclasses.replace(filled.settings, ntfy_url="https://ntfy.example/t", default_language="de")
    changes = [dnswatch.Change("example.org", "spf", "record", "v=spf1 mx -all", "v=spf1 a -all")]
    assert dnswatch.report(filled.db, settings, changes)
    title, message, data = sent[0]
    assert "DNS-Einträge geändert" in title
    assert "example.org · SPF: Eintrag geändert" in message and "v=spf1 mx -all → v=spf1 a -all" in message
    assert data["dns_changes"][0]["section"] == "spf"
    # only resolved problems: no message
    gone = json.dumps({"level": "bad", "text": "Kein SPF-Eintrag gefunden.", "args": {}})
    assert not dnswatch.report(filled.db, settings, [dnswatch.Change("example.org", "spf", "resolved", old=gone)])


def test_periodic_runs_dns_watch_daily(filled, monkeypatch):
    calls = []
    monkeypatch.setattr(dnswatch, "check", lambda db, s: calls.append(1) or [])
    filled.periodic()
    filled.periodic()
    assert calls == [1]
    filled.db.set_meta("last_dns_watch", "0")
    filled.settings = dataclasses.replace(filled.settings, dns_watch="off")
    filled.periodic()
    assert calls == [1]


def test_dns_page_lists_changes(c, filled, monkeypatch):
    monkeypatch.setattr(dnscheck, "check_domain", lambda d, s, m, refresh=False: sections())
    with filled.db.connect() as con:
        con.execute("INSERT INTO dns_changes (domain, section, kind, old, new, created_at) "
                    "VALUES ('example.org', 'spf', 'record', 'v=spf1 mx -all', 'v=spf1 a -all', 1790000000)")
    page = c.get("/domain/example.org/dns").text
    assert "Letzte Änderungen" in page and "SPF: Eintrag geändert" in page and "täglich" in page


def test_dns_watch_setting(c, filled):
    page = c.get("/settings").text
    assert 'name="dns_watch"' in page
    c.post("/settings", data={"dns_watch": "off"})
    assert filled.notify_settings().dns_watch == "off"
