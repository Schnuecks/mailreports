# SPDX-License-Identifier: AGPL-3.0-or-later
import json

from mailreports import i18n
from mailreports.explain import explain_record
from mailreports.sources import Source, classify, load_sources

POLICY = {"domain": "example.org", "adkim": "s", "aspf": "s"}


def rec(**kw):
    base = {"source_ip": "192.0.2.10", "count": 12, "disposition": "none", "dkim_eval": "pass", "spf_eval": "pass",
            "dmarc_pass": 1, "header_from": "example.org", "envelope_from": "example.org", "reasons": "[]",
            "dkim": json.dumps([{"domain": "example.org", "selector": "2026a", "result": "pass"}]),
            "spf": json.dumps([{"domain": "example.org", "result": "pass"}])}
    base.update(kw)
    return base


def info(**kw):
    base = {"ptr": None, "ptr_confirmed": 0, "country": None, "country_names": None, "asn": None, "as_org": None}
    base.update(kw)
    return base


def setup_function():
    i18n.set_language("de")


def test_own_server_passes(tmp_path):
    path = tmp_path / "s.toml"
    path.write_text('[[source]]\nname = "Eigener Server"\nkind = "own"\nips = ["192.0.2.0/24"]\n', encoding="utf-8")
    sources = load_sources(str(path))
    v = classify(sources, rec(), None)
    assert v.kind == "own"
    e = explain_record(rec(), v, None, POLICY)
    assert e.level == "ok"
    assert e.title == "DMARC bestanden"
    assert e.text == ("Diese 12 E-Mails stammen von Eigener Server: korrekt mit example.org signiert "
                      "(DKIM-Selektor 2026a), IP per SPF für example.org erlaubt.")


def test_relay_by_dkim_selector():
    src = [Source("Newsletter", "relay", dkim_selectors=["nl1"])]
    r = rec(source_ip="198.51.100.25", spf_eval="fail",
            dkim=json.dumps([{"domain": "example.org", "selector": "nl1", "result": "pass"}]))
    v = classify(src, r, None)
    assert v.kind == "relay" and v.source.name == "Newsletter"


def test_forwarding_guess():
    r = rec(source_ip="198.51.100.77", spf_eval="fail")
    v = classify([], r, None)
    assert v.kind == "forwarder"
    assert "aufgrund der Weiterleitung" in explain_record(r, v, info(ptr="mx.forward.test"), POLICY).text


def test_spoofer_in_plain_words():
    r = rec(source_ip="203.0.113.5", count=3, disposition="quarantine", dkim_eval="fail", spf_eval="fail",
            dmarc_pass=0, dkim="[]", spf=json.dumps([{"domain": "spam.invalid", "result": "softfail"}]))
    v = classify([], r, None)
    assert v.kind == "unknown"
    e = explain_record(r, v, info(country="CN", country_names='{"de": "China", "en": "China"}',
                                  asn=4134, as_org="Chinanet"), POLICY)
    assert e.level == "warn"
    assert "China" in e.text and "AS4134 Chinanet" in e.text
    assert "im Namen von example.org gesendet" in e.text
    assert "Quarantäne" in e.text


def test_english():
    i18n.set_language("en")
    e = explain_record(rec(), classify([], rec(), None), None, POLICY)
    assert e.title == "DMARC passed"
    assert e.text.startswith("These 12 emails came from unknown sender 192.0.2.10: correctly signed")


def test_translations_keep_placeholders():
    import re

    from mailreports.i18n import LANGUAGES, catalog
    for lang in LANGUAGES:
        for key, value in catalog(lang).items():
            assert set(re.findall(r"\{\w+\}", key)) == set(re.findall(r"\{\w+\}", value)), (lang, key)
