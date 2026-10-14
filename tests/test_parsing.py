# SPDX-License-Identifier: AGPL-3.0-or-later
from email.message import EmailMessage

import pytest

from mailreports import parsing
from tests.conftest import DMARC_XML, TLS_JSON, gz, zipped


def test_dmarc_fields():
    rep = parsing.parse_dmarc(DMARC_XML)
    assert rep.org_name == "google.com"
    assert rep.report_id == "1234567890"
    assert rep.domain == "example.org"
    assert rep.policy["p"] == "quarantine" and rep.policy["adkim"] == "s"
    assert len(rep.records) == 2
    good, bad = rep.records
    assert good.count == 12 and good.dmarc_pass
    assert good.dkim == [{"domain": "example.org", "selector": "2026a", "result": "pass", "human_result": ""}]
    assert bad.disposition == "quarantine" and not bad.dmarc_pass
    assert bad.spf[0]["result"] == "softfail"


def test_dmarc_with_namespace():
    xml = DMARC_XML.replace(b"<feedback>", b'<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">')
    assert parsing.parse_dmarc(xml).domain == "example.org"


def test_dmarc_rejects_entities():
    evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><feedback>&a;</feedback>'
    with pytest.raises(parsing.ReportError):
        parsing.parse_dmarc(evil)


@pytest.mark.parametrize("data", [b"<html></html>", b"<feedback><broken>", b"<feedback></feedback>"])
def test_dmarc_broken(data):
    with pytest.raises(parsing.ReportError):
        parsing.parse_dmarc(data)


def test_tls_fields():
    rep = parsing.parse_tls(TLS_JSON)
    assert rep.org_name == "Google Inc."
    assert rep.date_begin == 1791849600
    pol = rep.policies[0]
    assert pol.policy_type == "sts" and pol.success == 40 and pol.failure == 2
    assert pol.failures[0].result_type == "certificate-expired"
    assert pol.mx_hosts == ["mail.example.org"]


@pytest.mark.parametrize("data", [b"{}", b"[1]", b"{broken", b'{"policies": []}'])
def test_tls_broken(data):
    with pytest.raises(parsing.ReportError):
        parsing.parse_tls(data)


def test_unpack_gzip_and_zip():
    assert parsing.unpack(parsing.Payload("a.xml.gz", gz(DMARC_XML)))[0].data == DMARC_XML
    files = parsing.unpack(parsing.Payload("a.zip", zipped("a.xml", DMARC_XML)))
    assert files[0].data == DMARC_XML and files[0].name == "a.xml"


def test_unpack_bomb(monkeypatch):
    monkeypatch.setattr(parsing, "MAX_UNPACKED", 100)
    with pytest.raises(parsing.ReportError):
        parsing.unpack(parsing.Payload("a.gz", gz(b"x" * 1000)))


def test_kind_of():
    assert parsing.kind_of(b"\xef\xbb\xbf  <?xml") == "dmarc"
    assert parsing.kind_of(b'\n{"a": 1}') == "tls"
    assert parsing.kind_of(b"PK") is None


def test_attachments_by_content_type_and_name():
    msg = EmailMessage()
    msg["Subject"] = "Report"
    msg.set_content("see attachment")
    msg.add_attachment(gz(DMARC_XML), maintype="application", subtype="octet-stream", filename="r.xml.gz")
    msg.add_attachment(TLS_JSON, maintype="application", subtype="tlsrpt+json", filename="t.json")
    msg.add_attachment(b"hello", maintype="image", subtype="png", filename="logo.png")
    found = parsing.attachments(parsing.parse_mail(msg.as_bytes()))
    assert [p.name for p in found] == ["r.xml.gz", "t.json"]
