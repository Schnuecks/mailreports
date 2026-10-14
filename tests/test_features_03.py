# SPDX-License-Identifier: AGPL-3.0-or-later
"""0.3.0: original reports, export, sender page, search, retention, DNS check, advice, channels, metrics."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from mailreports import advice, dnscheck, notify, queries
from mailreports.ingest import ingest_payload
from mailreports.main import create_app
from mailreports.parsing import Payload
from mailreports.service import Service
from tests.conftest import DMARC_XML, TLS_JSON, make_settings

DE = {"accept-language": "de"}


@pytest.fixture
def filled(service):
    ingest_payload(service.db, Payload("a.xml", DMARC_XML))
    ingest_payload(service.db, Payload("t.json", TLS_JSON))
    return service


@pytest.fixture
def c(filled):
    with TestClient(create_app(filled), headers=DE) as client:
        yield client


def test_original_report_download(c):
    r = c.get("/reports/1/raw")
    assert r.status_code == 200 and r.content == DMARC_XML
    assert "attachment" in r.headers["content-disposition"]
    assert c.get("/tls/1/raw").content == TLS_JSON
    assert "XML herunterladen" in c.get("/reports/1").text
    assert c.get("/reports/99/raw").status_code == 404


def test_csv_export_escapes_formulas(filled):
    with filled.db.connect() as con:
        con.execute("UPDATE dmarc_records SET header_from = '=HYPERLINK(\"x\")' WHERE source_ip = '203.0.113.5'")
    with TestClient(create_app(filled)) as client:
        text = client.get("/export/dmarc.csv?days=365").text
    lines = text.strip().splitlines()
    assert lines[0].startswith("begin_utc,end_utc,reporter")
    assert len(lines) == 3
    assert "'=HYPERLINK" in text


def test_sender_page_and_search(c):
    r = c.get("/sources/203.0.113.5?days=365")
    assert r.status_code == 200 and "203.0.113.5" in r.text and "Zum Bericht" in r.text
    assert c.get("/sources/198.51.100.99").status_code == 404
    r = c.get("/search?q=203.0.113")
    assert "203.0.113.5" in r.text
    assert "google.com" in c.get("/search?q=google").text
    assert "2026a" in c.get("/search?q=2026a").text or "192.0.2.10" in c.get("/search?q=2026a").text


def test_retention_and_housekeeping(filled):
    with filled.db.connect() as con:
        con.execute("UPDATE dmarc_reports SET date_end = date_end - 500 * 86400, date_begin = date_begin - 500 * 86400")
    removed = filled.db.housekeeping(400)
    assert removed["dmarc"] == 1 and removed["tls"] == 0
    with filled.db.connect() as con:
        assert con.execute("SELECT COUNT(*) FROM dmarc_records").fetchone()[0] == 0
        assert con.execute("SELECT COUNT(*) FROM raw_reports WHERE kind = 'dmarc'").fetchone()[0] == 0
    assert filled.db.housekeeping(0) == {"dmarc": 0, "tls": 0}


# ---------------------------------------------------------------- DNS check

class FakeDns:
    def __init__(self):
        self.txt = {
            "_dmarc.example.org": ["v=DMARC1; p=none; rua=mailto:reports@other.example"],
            "example.org": ["v=spf1 include:a.example include:b.example ?all"],
            "a.example": ["v=spf1 " + " ".join(f"include:x{i}.example" for i in range(10)) + " -all"],
            "b.example": ["v=spf1 ip4:192.0.2.0/24 -all"],
            "2026a._domainkey.example.org": ["v=DKIM1; k=rsa; p="],
            "_smtp._tls.example.org": ["v=TLSRPTv1; rua=mailto:tls@example.org"],
        }

    def lookup(self, name):
        return self.txt.get(name, [])


def test_dns_check_findings(monkeypatch):
    fake = FakeDns()
    monkeypatch.setattr(dnscheck, "txt", fake.lookup)
    monkeypatch.setattr(dnscheck, "mx", lambda d: ["mail.example.org"])
    monkeypatch.setattr(dnscheck, "has_record", lambda name, t: False)
    dnscheck._cache.clear()
    sections = {s.key: s for s in dnscheck.check_domain("example.org", ["2026a"], "dmarc@example.org")}
    texts = lambda key: [f.text.format(**f.args) for f in sections[key].findings]  # noqa: E731
    assert sections["dmarc"].level == "bad"          # report address not authorised at the other domain
    assert any("p=none" in t for t in texts("dmarc"))
    assert any("dmarc@example.org" in t for t in texts("dmarc"))
    assert any("12 DNS-Abfragen" in t for t in texts("spf"))
    assert any("?all" in t for t in texts("spf"))
    assert any("widerrufen" in t for t in texts("dkim"))
    assert sections["mta_sts"].level == "info"
    assert sections["tlsrpt"].level == "ok"


def test_dns_page(c, monkeypatch):
    monkeypatch.setattr(dnscheck, "check_domain", lambda d, s, m, refresh=False: [])
    assert c.get("/domain/example.org/dns").status_code == 200
    assert c.get("/domain/unknown.invalid/dns").status_code == 404


def test_sts_fetch_refuses_internal_addresses(monkeypatch):
    monkeypatch.setattr(dnscheck.socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("10.0.0.5", 443))])
    with pytest.raises(dnscheck.DnsError):
        dnscheck.fetch_sts_policy("example.org")


def test_dkim_key_size():
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert dnscheck._key_bits(base64.b64encode(der).decode()) == ("RSA", 1024)


# ---------------------------------------------------------------- advice

def _days_of_reports(service, days: int, unknown_pass: bool = False):
    now = int(time.time())
    for d in range(days):
        begin = now - (d + 1) * 86400
        period = f"<begin>{begin}</begin><end>{begin + 86399}</end>".encode()
        xml = DMARC_XML.replace(b"1234567890", f"r{d}".encode()).replace(
            b"<begin>1791849600</begin><end>1791935999</end>", period)
        xml = xml.replace(b"<p>quarantine</p>", b"<p>none</p>")
        if unknown_pass:
            # an unlisted service: SPF passes for the domain, no DKIM
            xml = xml.replace(b"<disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf>",
                              b"<disposition>none</disposition><dkim>fail</dkim><spf>pass</spf>")
        ingest_payload(service.db, Payload("a.xml", xml))


def test_advice_needs_enough_data(filled):
    a = advice.policy_advice(filled.db, filled.sources, "example.org", {"p": "none"},
                             __import__("zoneinfo").ZoneInfo("UTC"))
    assert a.level == "info" and a.title == "Noch zu wenig Daten"


def test_advice_recommends_quarantine(service):
    _days_of_reports(service, 20)
    a = advice.policy_advice(service.db, service.sources, "example.org", {"p": "none", "adkim": "s", "aspf": "s"},
                             __import__("zoneinfo").ZoneInfo("UTC"))
    assert a.title == "p=quarantine ist möglich" and a.record.startswith("v=DMARC1; p=quarantine")


def test_advice_blocks_on_unknown_passing_source(service):
    _days_of_reports(service, 20, unknown_pass=True)
    a = advice.policy_advice(service.db, service.sources, "example.org", {"p": "none"},
                             __import__("zoneinfo").ZoneInfo("UTC"))
    assert a.level == "warn" and any("203.0.113.5" in str(args) for _t, args in a.points)


# ---------------------------------------------------------------- notifications and metrics

def test_all_channels(filled, monkeypatch):
    sent = []

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"status": 1}'

    def fake_urlopen(req, timeout=0, **kw):
        sent.append((req.full_url, json.loads(req.data) if req.data and req.data[:1] == b"{" else req.data))
        return Resp()

    class FakeSMTP:
        def __init__(self, *a, **k):
            pass

        def starttls(self, context=None):
            sent.append(("smtp", "starttls"))

        def login(self, u, p):
            pass

        def send_message(self, msg):
            sent.append(("smtp", msg["To"]))

        def quit(self):
            pass

    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    s = filled.settings
    s.ntfy_url, s.webhook_url = "https://ntfy.example/mailreports", "https://hooks.example/x"
    s.smtp_host, s.smtp_from, s.notify_email = "smtp.example", "dmarc@example.org", ["admin@example.org"]
    with filled.db.connect() as con:
        ids = [r[0] for r in con.execute("SELECT id FROM dmarc_reports")]
    assert notify.notify(filled.db, s, filled.sources, ids, []) == 1
    urls = [u for u, _ in sent]
    assert "https://ntfy.example" in urls and "https://hooks.example/x" in urls
    ntfy_body = next(b for u, b in sent if u == "https://ntfy.example")
    assert ntfy_body["topic"] == "mailreports" and "203.0.113.5" in ntfy_body["message"]
    assert ("smtp", "admin@example.org") in sent


def test_weekly_digest_text(filled):
    from zoneinfo import ZoneInfo
    text = notify.weekly_digest(filled.db, filled.settings, filled.sources, ZoneInfo("UTC"))
    assert text.startswith("Summary of the last 7 days") or text.startswith("Zusammenfassung")


def test_metrics_token(tmp_path):
    import ipaddress
    svc = Service(make_settings(tmp_path, auth_disabled=False, admin_password="admin-password-1", metrics_token="t0k",
                                trusted_proxies=[ipaddress.ip_network("10.0.0.1/32")]))
    ingest_payload(svc.db, Payload("a.xml", DMARC_XML))
    with TestClient(create_app(svc), client=("172.18.0.9", 1234)) as client:
        assert client.get("/metrics").status_code == 403                    # not the proxy, no token
        r = client.get("/metrics", headers={"authorization": "Bearer t0k"})
        assert r.status_code == 200 and "mailreports_reports{kind=\"dmarc\"} 1" in r.text
        data = client.get("/api/metrics?token=t0k").json()
        assert data["reports"]["dmarc"] == 1
        assert client.get("/", headers={"authorization": "Bearer t0k"}).status_code == 403   # token only for metrics


def test_metrics_page_for_signed_in(c):
    assert "mailreports_last_fetch_ok" in c.get("/metrics").text
    assert queries.metrics is not None


def test_null_mx():
    sec = dnscheck.check_mx("example.org", [""])
    assert sec.record == "MX 0 ." and "Null-MX" in sec.findings[0].text
