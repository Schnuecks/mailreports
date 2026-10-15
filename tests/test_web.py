# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest
from fastapi.testclient import TestClient

from mailreports.ingest import ingest_payload
from mailreports.main import create_app
from mailreports.parsing import Payload
from mailreports.service import Service
from tests.conftest import DMARC_XML, TLS_JSON, gz, make_settings


@pytest.fixture
def filled(service):
    ingest_payload(service.db, Payload("a.xml", DMARC_XML))
    ingest_payload(service.db, Payload("t.json", TLS_JSON))
    return service


def test_healthz(client):
    assert client.get("/healthz").json()["status"] == "ok"


def test_empty_overview(client):
    r = client.get("/", headers={"accept-language": "de"})
    assert r.status_code == 200 and "Noch keine Berichte" in r.text


PAGES = ["/?days=365", "/domain/example.org", "/reports?days=365", "/reports?failed=1&days=365", "/reports/1",
         "/sources?days=365", "/tls?days=365", "/tls/1", "/help", "/status"]


@pytest.mark.parametrize("path", PAGES)
def test_pages(filled, path):
    with TestClient(create_app(filled)) as c:
        for lang in ("de", "en"):
            r = c.get(path, headers={"accept-language": lang})
            assert r.status_code == 200, (path, lang)
            assert "{" not in r.text.split("<body>")[1].replace("{%", ""), "unformatted placeholder"
            assert 'style="' not in r.text, "inline styles are blocked by the CSP"


def test_report_detail_explains(filled):
    with TestClient(create_app(filled)) as c:
        text = c.get("/reports/1", headers={"accept-language": "de"}).text
    assert "Own mail server" in text
    assert "hat im Namen von example.org gesendet" in text


def test_not_found(client):
    assert client.get("/reports/999").status_code == 404
    assert client.get("/domain/nothing.invalid").status_code == 404


def test_upload(client, service):
    r = client.post("/upload", files=[("files", ("a.xml.gz", gz(DMARC_XML))), ("files", ("x.txt", b"nonsense"))],
                    follow_redirects=False)
    assert r.status_code == 303 and "uploaded=1-0-0-1" in r.headers["location"]


def test_cross_site_post_refused(client):
    assert client.post("/fetch", headers={"sec-fetch-site": "cross-site"}).status_code == 403
    assert client.post("/fetch", headers={"origin": "https://evil.test"}).status_code == 403
    r = client.post("/fetch", headers={"origin": "http://testserver"}, follow_redirects=False)
    assert r.status_code == 303


def test_auth_header_needs_trusted_proxies(tmp_path):
    with pytest.raises(SystemExit, match="TRUSTED_PROXIES"):
        Service(make_settings(tmp_path, auth_header="Remote-User"))


def test_auth_header(tmp_path):
    import ipaddress
    svc = Service(make_settings(tmp_path, auth_header="Remote-User", allowed_groups=["admins"],
                                trusted_proxies=[ipaddress.ip_network("10.0.0.1/32")]))
    with TestClient(create_app(svc), client=("10.0.0.2", 5000)) as c:
        assert c.get("/", headers={"Remote-User": "a", "Remote-Groups": "admins"}).status_code == 403
    with TestClient(create_app(svc), client=("10.0.0.1", 5000)) as c:
        assert c.get("/").status_code == 401
        assert c.get("/", headers={"Remote-User": "a", "Remote-Groups": "users"}).status_code == 403
        r = c.get("/", headers={"Remote-User": "a", "Remote-Groups": "users,admins", "Remote-Name": "Andrea"})
        assert r.status_code == 200 and "Andrea" in r.text
        assert c.get("/healthz").status_code == 200


def test_trusted_proxies(tmp_path):
    import ipaddress
    svc = Service(make_settings(tmp_path, trusted_proxies=[ipaddress.ip_network("10.0.0.0/8")]))
    with TestClient(create_app(svc)) as c:   # test client connects as "testclient"
        assert c.get("/").status_code == 403
        assert c.get("/healthz").status_code == 200


def test_language_cookie(client):
    r = client.get("/lang/en", follow_redirects=False)
    assert r.cookies.get("lang") == "en"
    client.cookies.set("lang", "en")
    assert "Overview" in client.get("/").text


def test_language_redirect_stays_on_host(client):
    r = client.get("/lang/de", headers={"referer": "https://testserver/reports?days=7"}, follow_redirects=False)
    assert r.headers["location"] == "/reports?days=7"
    r = client.get("/lang/de", headers={"referer": "https://evil.test/x"}, follow_redirects=False)
    assert r.headers["location"] == "/"


def test_client_ip_behind_trusted_proxy(tmp_path):
    """Sign-in limits and the sign-in log need the visitor's address, not the proxy's."""
    import ipaddress as _ip
    from types import SimpleNamespace

    from mailreports import web
    settings = SimpleNamespace(trusted_proxies=[_ip.ip_network("172.20.1.1/32")])
    app = SimpleNamespace(state=SimpleNamespace(svc=SimpleNamespace(settings=settings)))

    def req(peer, xff=""):
        return SimpleNamespace(client=SimpleNamespace(host=peer), app=app,
                               headers={"x-forwarded-for": xff} if xff else {})
    assert web.client_ip(req("172.20.1.1", "203.0.113.7")) == "203.0.113.7"
    # a forged first entry is ignored, the proxy appends the real address at the end
    assert web.client_ip(req("172.20.1.1", "198.51.100.1, 203.0.113.7")) == "203.0.113.7"
    # from an untrusted peer the header counts for nothing
    assert web.client_ip(req("198.51.100.9", "203.0.113.7")) == "198.51.100.9"
    assert web.client_ip(req("172.20.1.1", "garbage")) == "172.20.1.1"
    settings.trusted_proxies = []
    assert web.client_ip(req("172.20.1.1", "203.0.113.7")) == "172.20.1.1"


def test_security_headers(tmp_path):
    from fastapi.testclient import TestClient

    from mailreports.main import content_security_policy, create_app
    from mailreports.service import Service
    from tests.conftest import make_settings
    csp = content_security_policy("")
    img = next(d for d in csp.split("; ") if d.startswith("img-src"))
    assert img == "img-src 'self' data:" and "https:" not in img
    assert "base-uri 'none'" in csp and "object-src 'none'" in csp
    img = next(d for d in content_security_policy("https://cdn.example/logo.svg").split("; ")
               if d.startswith("img-src"))
    assert img == "img-src 'self' data: https://cdn.example"
    assert "https://" not in content_security_policy("/static/logo.svg").split("img-src")[1].split(";")[0]
    r = TestClient(create_app(Service(make_settings(tmp_path)))).get("/")
    assert r.headers["cross-origin-opener-policy"] == "same-origin"
    assert r.headers["cross-origin-embedder-policy"] == "credentialless"
    assert r.headers["cross-origin-resource-policy"] == "same-origin"
    assert "camera=()" in r.headers["permissions-policy"]
    assert "object-src 'none'" in r.headers["content-security-policy"]
