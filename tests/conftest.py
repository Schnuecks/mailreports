# SPDX-License-Identifier: AGPL-3.0-or-later
import gzip
import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from mailreports.config import Settings
from mailreports.main import create_app
from mailreports.service import Service

DMARC_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>1234567890</report_id>
    <date_range><begin>1791849600</begin><end>1791935999</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.org</domain><adkim>s</adkim><aspf>s</aspf><p>quarantine</p><sp>quarantine</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.10</source_ip><count>12</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.org</header_from><envelope_from>example.org</envelope_from></identifiers>
    <auth_results>
      <dkim><domain>example.org</domain><selector>2026a</selector><result>pass</result></dkim>
      <spf><domain>example.org</domain><scope>mfrom</scope><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>203.0.113.5</source_ip><count>3</count>
      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.org</header_from></identifiers>
    <auth_results><spf><domain>spam.invalid</domain><result>softfail</result></spf></auth_results>
  </record>
</feedback>
"""

TLS_JSON = b"""{
  "organization-name": "Google Inc.",
  "date-range": {"start-datetime": "2026-10-13T00:00:00Z", "end-datetime": "2026-10-13T23:59:59Z"},
  "contact-info": "smtp-tls-reporting@google.com",
  "report-id": "2026-10-13T00:00:00Z_example.org",
  "policies": [{
    "policy": {"policy-type": "sts", "policy-string": ["version: STSv1", "mode: enforce"],
               "policy-domain": "example.org", "mx-host": ["mail.example.org"]},
    "summary": {"total-successful-session-count": 40, "total-failure-session-count": 2},
    "failure-details": [{"result-type": "certificate-expired", "sending-mta-ip": "198.51.100.200",
                         "receiving-mx-hostname": "mail.example.org", "failed-session-count": 2}]
  }]
}"""

SOURCES = """
[[source]]
name = "Own mail server"
kind = "own"
ips = ["192.0.2.10"]

[[source]]
name = "Newsletter service"
kind = "relay"
dkim_selectors = ["nl1"]
"""


def gz(data: bytes) -> bytes:
    return gzip.compress(data)


def zipped(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, data)
    return buf.getvalue()


def make_settings(tmp_path, **kw) -> Settings:
    src = tmp_path / "sources.toml"
    src.write_text(SOURCES, encoding="utf-8")
    base = dict(data_dir=tmp_path / "data", background_tasks=False, dns_lookups=False, sources_file=str(src),
                auth_disabled=True)
    base.update(kw)
    return Settings(**base)


@pytest.fixture
def service(tmp_path):
    return Service(make_settings(tmp_path))


@pytest.fixture
def client(service):
    with TestClient(create_app(service)) as c:
        yield c
