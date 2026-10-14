# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Create realistic demo reports for example.org / example.net.

    python tools/make_demo.py OUT_DIR [--days 30]

Writes gzipped DMARC XML and TLS JSON files plus a sources.toml. Import them with
    DATA_DIR=... SOURCES_FILE=OUT_DIR/sources.toml python -m mailreports import OUT_DIR/*.gz
Only documentation addresses (RFC 5737 / RFC 3849) are used.
"""
from __future__ import annotations

import argparse
import gzip
import json
import random
import time
from datetime import UTC, datetime
from pathlib import Path
from xml.sax.saxutils import escape

OWN_V4, OWN_V6 = "192.0.2.10", "2001:db8::10"
NEWSLETTER = "198.51.100.25"
FORWARDER = "198.51.100.77"
SPOOFERS = ["203.0.113.5", "203.0.113.66", "203.0.113.140"]
REPORTERS = [("google.com", "noreply-dmarc-support@google.com"),
             ("Outlook.com", "dmarcreport@microsoft.com"),
             ("Yahoo", "dmarchelp@yahooinc.com"),
             ("web.de", "dmarc@web.de")]

SOURCES = """\
[[source]]
name = "Own mail server"
kind = "own"
ips = ["192.0.2.10", "2001:db8::10"]
ptr = ["mail.example.org"]

[[source]]
name = "Newsletter service"
kind = "relay"
dkim_selectors = ["nl1", "nl2"]
dkim_domains = ["example.org"]
note = "Only for newsletters"
"""


def record(ip, count, disp, dkim_eval, spf_eval, header_from, envelope_from, dkim, spf, reason=None):
    dk = "".join(f"<dkim><domain>{d}</domain><selector>{s}</selector><result>{r}</result></dkim>" for d, s, r in dkim)
    sp = "".join(f"<spf><domain>{d}</domain><scope>mfrom</scope><result>{r}</result></spf>" for d, r in spf)
    rs = f"<reason><type>{reason}</type></reason>" if reason else ""
    return (f"<record><row><source_ip>{ip}</source_ip><count>{count}</count><policy_evaluated>"
            f"<disposition>{disp}</disposition><dkim>{dkim_eval}</dkim><spf>{spf_eval}</spf>{rs}"
            f"</policy_evaluated></row><identifiers><header_from>{header_from}</header_from>"
            f"<envelope_from>{envelope_from}</envelope_from></identifiers>"
            f"<auth_results>{dk}{sp}</auth_results></record>")


def dmarc_xml(org, email, rid, begin, end, domain, records):
    return (f'<?xml version="1.0" encoding="UTF-8"?><feedback><report_metadata>'
            f"<org_name>{escape(org)}</org_name><email>{email}</email><report_id>{rid}</report_id>"
            f"<date_range><begin>{begin}</begin><end>{end}</end></date_range></report_metadata>"
            f"<policy_published><domain>{domain}</domain><adkim>s</adkim><aspf>s</aspf>"
            f"<p>quarantine</p><sp>quarantine</sp><pct>100</pct></policy_published>"
            + "".join(records) + "</feedback>").encode()


def day_records(rnd: random.Random, domain: str, day: int) -> list[str]:
    recs = [record(OWN_V4, rnd.randint(8, 40), "none", "pass", "pass", domain, domain,
                   [(domain, "2026a", "pass")], [(domain, "pass")])]
    if rnd.random() < .6:
        recs.append(record(OWN_V6, rnd.randint(1, 12), "none", "pass", "pass", domain, domain,
                           [(domain, "2026a", "pass")], [(domain, "pass")]))
    if domain == "example.org" and rnd.random() < .5:
        recs.append(record(NEWSLETTER, rnd.randint(20, 120), "none", "pass", "fail", domain, "bounce.mailer.test",
                           [(domain, "nl1", "pass"), ("mailer.test", "s1", "pass")], [("bounce.mailer.test", "pass")]))
    if rnd.random() < .25:
        recs.append(record(FORWARDER, rnd.randint(1, 3), "none", "pass", "fail", domain, domain,
                           [(domain, "2026a", "pass")], [(domain, "fail")]))
    if rnd.random() < .3:
        recs.append(record(rnd.choice(SPOOFERS), rnd.randint(1, 6), "quarantine", "fail", "fail", domain,
                           "spam.invalid", [], [("spam.invalid", "softfail")]))
    if day == 3:
        recs.append(record(FORWARDER, 2, "quarantine", "fail", "fail", domain, domain,
                           [(domain, "2026a", "fail")], [(domain, "fail")]))
    return recs


def tls_json(org, rid, start, end, domain, failures):
    return json.dumps({
        "organization-name": org, "contact-info": "smtp-tls-reporting@" + org.lower().replace(" ", ""),
        "report-id": rid,
        "date-range": {"start-datetime": datetime.fromtimestamp(start, UTC).isoformat().replace("+00:00", "Z"),
                       "end-datetime": datetime.fromtimestamp(end, UTC).isoformat().replace("+00:00", "Z")},
        "policies": [
            {"policy": {"policy-type": "sts", "policy-string": ["version: STSv1", "mode: enforce",
                                                                f"mx: mail.{domain}", "max_age: 604800"],
                        "policy-domain": domain, "mx-host": [f"mail.{domain}"]},
             "summary": {"total-successful-session-count": 40 - failures, "total-failure-session-count": failures},
             "failure-details": ([{"result-type": "certificate-expired", "sending-mta-ip": "198.51.100.200",
                                   "receiving-mx-hostname": f"mail.{domain}", "receiving-ip": OWN_V4,
                                   "failed-session-count": failures}] if failures else [])},
        ]}).encode()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    ap.add_argument("--days", type=int, default=30)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    rnd = random.Random(7)
    today = int(time.time()) // 86400 * 86400
    n = 0
    for day in range(args.days, 0, -1):
        begin, end = today - day * 86400, today - (day - 1) * 86400 - 1
        for domain in ("example.org", "example.net"):
            for org, email in REPORTERS[: 2 + rnd.randint(0, 2)]:
                rid = f"{org.split('.')[0].lower()}-{domain}-{begin}"
                data = dmarc_xml(org, email, rid, begin, end, domain, day_records(rnd, domain, day))
                (args.out / f"{org}!{domain}!{begin}!{end}.xml.gz").write_bytes(gzip.compress(data))
                n += 1
        fails = 3 if day == 5 else 0
        data = tls_json("Google Inc.", f"tls-{begin}", begin, end, "example.org", fails)
        (args.out / f"google.com!example.org!{begin}!{end}.json.gz").write_bytes(gzip.compress(data))
        n += 1
    (args.out / "sources.toml").write_text(SOURCES, encoding="utf-8")
    print(f"{n} files written to {args.out}")


if __name__ == "__main__":
    main()
