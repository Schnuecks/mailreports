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
    assert "hat versucht, als example.org zu senden" in text


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


def test_no_sign_in_configured_refuses_start(tmp_path):
    with pytest.raises(SystemExit, match="ADMIN_PASSWORD"):
        Service(make_settings(tmp_path, auth_disabled=False))


@pytest.mark.parametrize("configured", ["correct horse battery", "argon2"])
def test_password_login(tmp_path, configured):
    from mailreports import auth
    password = "correct horse battery"
    stored = auth.hash_password(password) if configured == "argon2" else password
    svc = Service(make_settings(tmp_path, auth_disabled=False, admin_password=stored))
    with TestClient(create_app(svc)) as c:
        r = c.get("/reports?days=7", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login?next=/reports%3Fdays%3D7"
        assert c.post("/fetch", follow_redirects=False).status_code == 401
        assert c.get("/healthz").status_code == 200
        assert c.get("/static/style.css").status_code == 200
        assert c.post("/login", data={"password": "wrong", "next": "/"}).status_code == 401
        r = c.post("/login", data={"password": password, "next": "/reports?days=7"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/reports?days=7"
        assert c.get("/").status_code == 200
        c.post("/logout")
        assert c.get("/", follow_redirects=False).status_code == 303


def test_login_rate_limit_and_safe_redirect(tmp_path):
    svc = Service(make_settings(tmp_path, auth_disabled=False, admin_password="correct horse battery"))
    with TestClient(create_app(svc)) as c:
        r = c.post("/login", data={"password": "correct horse battery", "next": "//evil.test/"},
                   follow_redirects=False)
        assert r.headers["location"] == "/"
        c.post("/logout")
        for _ in range(5):
            c.post("/login", data={"password": "nope"})
        assert c.post("/login", data={"password": "correct horse battery"}).status_code == 429


def test_session_cookie_is_signed(tmp_path):
    from mailreports import auth
    s = auth.Sessions(b"k" * 32, "pw")
    token = s.create()
    assert s.valid(token)
    assert not s.valid(token[:-2] + "xx")
    assert not auth.Sessions(b"k" * 32, "other").valid(token)   # new password signs everybody out
