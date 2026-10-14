# SPDX-License-Identifier: AGPL-3.0-or-later
from mailreports import notify
from mailreports.ingest import ingest_payload
from mailreports.parsing import Payload
from tests.conftest import DMARC_XML, TLS_JSON


def test_findings_and_cooldown(service, monkeypatch):
    sent = []
    monkeypatch.setattr(notify, "send_pushover", lambda s, title, msg, priority=0: sent.append((title, msg)))
    service.settings.pushover_token, service.settings.pushover_user = "t", "u"
    out = ingest_payload(service.db, Payload("a.xml", DMARC_XML))
    out.merge(ingest_payload(service.db, Payload("t.json", TLS_JSON)))
    n = notify.notify(service.db, service.settings, service.sources, out.new_dmarc, out.new_tls)
    assert n == 2
    title, msg = sent[0]
    assert "203.0.113.5" in msg and "certificate-expired" in msg
    assert "192.0.2.10" not in msg     # own server passed, nothing to report
    # same findings again: inside the cooldown, no second message
    assert notify.notify(service.db, service.settings, service.sources, out.new_dmarc, out.new_tls) == 0
    assert len(sent) == 1


def test_disabled_without_credentials(service):
    assert notify.notify(service.db, service.settings, service.sources, [1], []) == 0
