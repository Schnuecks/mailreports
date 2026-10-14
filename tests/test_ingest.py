# SPDX-License-Identifier: AGPL-3.0-or-later
from email.message import EmailMessage

from mailreports.ingest import ingest_mail, ingest_payload
from mailreports.parsing import Payload
from tests.conftest import DMARC_XML, TLS_JSON, gz, zipped


def mail(*attachments) -> bytes:
    msg = EmailMessage()
    msg["From"] = "noreply-dmarc-support@google.com"
    msg["Subject"] = "Report domain: example.org"
    msg["Message-ID"] = "<1@test>"
    msg.set_content("report")
    for name, data, ctype in attachments:
        main, sub = ctype.split("/")
        msg.add_attachment(data, maintype=main, subtype=sub, filename=name)
    return msg.as_bytes()


def test_mail_with_dmarc_and_tls(service):
    out = ingest_mail(service.db, mail(("r.zip", zipped("r.xml", DMARC_XML), "application/zip"),
                                       ("t.json.gz", gz(TLS_JSON), "application/tlsrpt+gzip")))
    assert len(out.new_dmarc) == 1 and len(out.new_tls) == 1 and out.status == "new"
    with service.db.connect() as con:
        assert con.execute("SELECT COUNT(*) FROM dmarc_records").fetchone()[0] == 2
        assert con.execute("SELECT status FROM mails").fetchone()[0] == "new"
        assert con.execute("SELECT COUNT(*) FROM tls_failures").fetchone()[0] == 1


def test_duplicate_is_ignored(service):
    ingest_payload(service.db, Payload("a.xml", DMARC_XML))
    out = ingest_mail(service.db, mail(("r.xml.gz", gz(DMARC_XML), "application/gzip")))
    assert out.duplicates == 1 and not out.new_dmarc and out.status == "duplicate"
    with service.db.connect() as con:
        assert con.execute("SELECT COUNT(*) FROM dmarc_records").fetchone()[0] == 2


def test_broken_attachment_is_logged(service):
    out = ingest_mail(service.db, mail(("r.xml.gz", b"\x1f\x8bbroken", "application/gzip")))
    assert out.status == "error" and "gzip" in out.errors[0]
    out = ingest_mail(service.db, mail())
    assert out.status == "error" and out.errors == ["no attachment"]


def test_unreadable_mail_does_not_raise(service):
    out = ingest_mail(service.db, b"\x00\xff" * 10)
    assert out.status in ("error", "empty")


def test_reports_for_other_domains_are_not_stored(service):
    """The report address is public: with DOMAINS set, made-up reports for other domains are dropped."""
    out = ingest_payload(service.db, Payload("a.xml", DMARC_XML), domains=["example.net"])
    assert not out.new_dmarc and "not in DOMAINS" in out.errors[0]
    out = ingest_payload(service.db, Payload("t.json", TLS_JSON), domains=["example.net"])
    assert not out.new_tls and out.errors
    # own domain (and subdomains) are stored
    assert ingest_payload(service.db, Payload("a.xml", DMARC_XML), domains=["org"]).new_dmarc
    assert ingest_payload(service.db, Payload("t.json", TLS_JSON), domains=["example.org"]).new_tls
