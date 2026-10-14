# SPDX-License-Identifier: AGPL-3.0-or-later
"""Built-in accounts: setup, sign-in, second factor, passkeys, single sign-on, roles."""
import base64
import hashlib
import json
import re
import secrets
import struct
import time
from urllib.parse import parse_qs, urlparse

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from mailreports import accounts, oidc, totp
from mailreports.main import create_app
from mailreports.service import Service
from tests.conftest import make_settings

ADMIN_PW = "admin-password-123"
USER_PW = "reader-password-456"


def app_client(tmp_path, **kw) -> tuple[TestClient, Service]:
    svc = Service(make_settings(tmp_path, auth_disabled=False, **kw))
    return TestClient(create_app(svc), headers={"accept-language": "de"}), svc


def csrf_of(client) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', client.get("/account").text).group(1)


def login(client, username, password, next_url="/"):
    return client.post("/login", data={"username": username, "password": password, "next": next_url},
                       follow_redirects=False)


@pytest.fixture
def two_users(tmp_path):
    client, svc = app_client(tmp_path, admin_password=ADMIN_PW)
    with svc.db.connect() as con:
        accounts.create_user(con, "reader", USER_PW)
    return client, svc


def test_setup_creates_first_admin(tmp_path):
    client, svc = app_client(tmp_path)
    assert client.get("/", follow_redirects=False).headers["location"] == "/setup"
    with svc.db.connect() as con:
        code = accounts.setup_code(con)
    data = {"code": "WRONG", "username": "alice", "password": ADMIN_PW, "repeat": ADMIN_PW}
    assert client.post("/setup", data=data).status_code == 401
    data["code"] = code.lower()
    r = client.post("/setup", data=data, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/").status_code == 200
    assert client.get("/users").status_code == 200          # first account is admin
    assert client.get("/setup", follow_redirects=False).headers["location"] == "/"


def test_admin_password_seeds_account(tmp_path):
    client, _ = app_client(tmp_path, admin_password=accounts.hash_password(ADMIN_PW), admin_username="root")
    assert login(client, "root", ADMIN_PW).status_code == 303


def test_login_flow_and_redirects(two_users):
    client, _ = two_users
    r = client.get("/reports?days=7", follow_redirects=False)
    assert r.headers["location"] == "/login?next=/reports%3Fdays%3D7"
    assert client.post("/fetch", follow_redirects=False).status_code == 401
    assert client.get("/healthz").status_code == 200
    assert client.get("/static/style.css").status_code == 200
    assert login(client, "reader", "wrong").status_code == 401
    r = login(client, "reader", USER_PW, "//evil.test/")
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert "__Host-" not in r.headers["set-cookie"]          # plain HTTP in tests
    assert client.get("/").status_code == 200
    client.post("/logout", data={"csrf": csrf_of(client)})
    assert client.get("/", follow_redirects=False).status_code == 303


def test_rate_limit_per_user(two_users):
    client, _ = two_users
    for _ in range(5):
        login(client, "reader", "nope")
    assert login(client, "reader", USER_PW).status_code == 429


def test_roles_and_csrf(two_users):
    client, _ = two_users
    login(client, "reader", USER_PW)
    assert client.get("/").status_code == 200
    assert client.get("/users").status_code == 403
    assert client.post("/fetch", data={"csrf": csrf_of(client)}).status_code == 403   # admins only
    client.post("/logout", data={"csrf": csrf_of(client)})
    login(client, "admin", ADMIN_PW)
    assert client.post("/fetch", data={"csrf": "wrong"}, follow_redirects=False).status_code == 403
    assert client.post("/fetch", data={"csrf": csrf_of(client)}, follow_redirects=False).status_code == 303


def test_user_management_keeps_an_admin(two_users):
    client, svc = two_users
    login(client, "admin", ADMIN_PW)
    csrf = csrf_of(client)
    r = client.post("/users/new", data={"csrf": csrf, "username": "carol", "password": "carol-password-1"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert login(TestClient(client.app), "carol", "carol-password-1").status_code == 303
    with svc.db.connect() as con:
        admin_id = con.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()[0]
    assert client.post(f"/users/{admin_id}/delete", data={"csrf": csrf}).status_code == 400
    r = client.post(f"/users/{admin_id}", data={"csrf": csrf, "enabled": "1"})   # remove own admin right
    assert r.status_code == 400


def enable_totp(client) -> tuple[str, str]:
    """Sets up the authenticator app; returns (secret, first recovery code)."""
    csrf = csrf_of(client)
    page = client.post("/account/2fa/start", data={"csrf": csrf}).text
    secret = re.search(r"<code>([A-Z2-7 ]+)</code>", page).group(1).replace(" ", "")
    code = totp._code(secret, int(time.time() // 30))
    page = client.post("/account/2fa/confirm", data={"csrf": csrf, "code": code}).text
    recovery = re.findall(r"<code>([A-Z2-9]{4}-[A-Z2-9]{4})</code>", page)
    assert len(recovery) == 8
    return secret, recovery[0]


def test_totp_and_recovery_code(two_users):
    client, _ = two_users
    login(client, "reader", USER_PW)
    secret, recovery = enable_totp(client)
    client.post("/logout", data={"csrf": csrf_of(client)})
    r = login(client, "reader", USER_PW)
    assert r.status_code == 200 and "Zweiter Faktor" in r.text
    pending = re.search(r'name="pending" value="([^"]+)"', r.text).group(1)
    assert client.post("/login/code", data={"pending": pending, "code": "000000"}).status_code == 401
    next_code = totp._code(secret, int(time.time() // 30) + 1)   # the first code was already used
    r = client.post("/login/code", data={"pending": pending, "code": next_code}, follow_redirects=False)
    assert r.status_code == 303
    client.post("/logout", data={"csrf": csrf_of(client)})
    pending = re.search(r'name="pending" value="([^"]+)"', login(client, "reader", USER_PW).text).group(1)
    r = client.post("/login/code", data={"pending": pending, "code": recovery.lower()}, follow_redirects=False)
    assert r.status_code == 303
    client.post("/logout", data={"csrf": csrf_of(client)})
    pending = re.search(r'name="pending" value="([^"]+)"', login(client, "reader", USER_PW).text).group(1)
    assert client.post("/login/code", data={"pending": pending, "code": recovery}).status_code == 401


def test_totp_secret_encrypted_with_secret_key(tmp_path):
    client, svc = app_client(tmp_path, admin_password=ADMIN_PW, secret_key="k" * 32)
    login(client, "admin", ADMIN_PW)
    enable_totp(client)
    with svc.db.connect() as con:
        assert con.execute("SELECT totp_secret FROM users").fetchone()[0].startswith("enc:v1:")


# ---------------------------------------------------------------- passkeys

def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class Authenticator:
    """A passkey: creates keys and signs like a real device."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = secrets.token_bytes(16)
        self.count = 0

    def _cose(self) -> bytes:
        nums = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})

    def create(self, options: dict, origin: str = "http://testserver") -> dict:
        client = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": origin}).encode()
        auth = (hashlib.sha256(options["rp"]["id"].encode()).digest() + bytes([0x45]) + struct.pack(">I", 0)
                + bytes(16) + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose())
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64(self.cred_id), "rawId": b64(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64(client), "attestationObject": b64(att)},
                "clientExtensionResults": {}}

    def get(self, options: dict, origin: str = "http://testserver") -> dict:
        self.count += 1
        client = json.dumps({"type": "webauthn.get", "challenge": options["challenge"], "origin": origin}).encode()
        auth = hashlib.sha256(options["rpId"].encode()).digest() + bytes([0x05]) + struct.pack(">I", self.count)
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64(self.cred_id), "rawId": b64(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64(client), "authenticatorData": b64(auth), "signature": b64(sig)},
                "clientExtensionResults": {}}


def add_passkey(client) -> tuple[Authenticator, object]:
    key = Authenticator()
    csrf = csrf_of(client)
    opts = client.post("/account/passkeys/options", json={"csrf": csrf}).json()
    assert opts["options"]["rp"]["id"] == "testserver"
    resp = client.post("/account/passkeys", json={"csrf": csrf, "token": opts["token"], "name": "Laptop",
                                                  "credential": key.create(opts["options"])})
    return key, resp


def test_passkey_register_and_sign_in_without_password(two_users):
    client, _ = two_users
    login(client, "reader", USER_PW)
    assert client.post("/account/passkeys/options", json={"csrf": "wrong"}).status_code == 403
    key, resp = add_passkey(client)
    assert "Wiederherstellungscodes" in resp.text     # first second factor: codes are shown once
    client.post("/logout", data={"csrf": csrf_of(client)})
    opts = client.post("/login/passkey/options").json()
    assert opts["options"]["userVerification"] == "required"
    r = client.post("/login/passkey", follow_redirects=False,
                    json={"token": opts["token"], "next": "/tls", "credential": key.get(opts["options"])})
    assert r.status_code == 303 and r.headers["location"] == "/tls"
    # wrong origin is refused
    client.post("/logout", data={"csrf": csrf_of(client)})
    opts = client.post("/login/passkey/options").json()
    r = client.post("/login/passkey", json={"token": opts["token"],
                                            "credential": key.get(opts["options"], origin="https://evil.test")})
    assert r.status_code == 400


def test_passkey_as_second_factor(two_users):
    client, _ = two_users
    login(client, "reader", USER_PW)
    key, _ = add_passkey(client)
    client.post("/logout", data={"csrf": csrf_of(client)})
    page = login(client, "reader", USER_PW).text
    pending = re.search(r'data-pending="([^"]+)"', page).group(1)
    opts = client.post("/login/code/passkey/options", json={"pending": pending}).json()
    r = client.post("/login/code/passkey", json={"pending": pending, "token": opts["token"],
                                                 "credential": key.get(opts["options"])}, follow_redirects=False)
    assert r.status_code == 303


# ---------------------------------------------------------------- single sign-on

ISSUER = "https://auth.example.com"


def jwt(claims: dict) -> str:
    def part(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    return f"{part({'alg': 'RS256'})}.{part(claims)}.c2ln"


class FakeProvider:
    def __init__(self):
        self.who = {"sub": "u-1", "preferred_username": "reader", "email": "reader@example.com", "groups": []}
        self.nonces: dict[str, str] = {}

    def authorize(self, url: str) -> str:
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        assert q["code_challenge_method"] == "S256"
        code = f"code-{len(self.nonces)}"
        self.nonces[code] = q["nonce"]
        return f"{urlparse(q['redirect_uri']).path}?code={code}&state={q['state']}"

    def http_json(self, url: str, data: dict | None = None, token: str = "") -> dict:
        if url.endswith("/.well-known/openid-configuration"):
            return {"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token"}
        if url.endswith("/token"):
            claims = {"iss": ISSUER, "aud": ["mailreports"], "exp": int(time.time()) + 300,
                      "nonce": self.nonces[data["code"]], **self.who}
            return {"id_token": jwt(claims), "access_token": "at"}
        raise AssertionError(url)


@pytest.fixture
def provider(monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(oidc, "_http_json", fake.http_json)
    oidc._discovery.clear()
    return fake


def sso(client, provider):
    r = client.get("/login/oidc?next=/sources", follow_redirects=False)
    assert r.headers["location"].startswith(f"{ISSUER}/authorize")
    return client.get(provider.authorize(r.headers["location"]), follow_redirects=False)


def test_sso_links_existing_account(tmp_path, provider):
    client, svc = app_client(tmp_path, admin_password=ADMIN_PW, oidc_issuer=ISSUER, oidc_client_id="mailreports",
                             oidc_admin_group="admins")
    with svc.db.connect() as con:
        accounts.create_user(con, "reader", USER_PW, email="reader@example.com")
    assert "Mit SSO anmelden" in client.get("/login").text
    provider.who["email_verified"] = True
    r = sso(client, provider)
    assert r.status_code == 303 and r.headers["location"] == "/sources"
    assert client.get("/users").status_code == 403
    with svc.db.connect() as con:
        assert con.execute("SELECT oidc_sub FROM users WHERE username = 'reader'").fetchone()[0] == "u-1"
    # admin group gives admin rights
    client.post("/logout", data={"csrf": csrf_of(client)})
    provider.who["groups"] = ["admins"]
    sso(client, provider)
    assert client.get("/users").status_code == 200


def test_sso_without_account_and_without_cookie(tmp_path, provider):
    client, _ = app_client(tmp_path, admin_password=ADMIN_PW, oidc_issuer=ISSUER, oidc_client_id="mailreports")
    provider.who["preferred_username"] = "stranger"
    provider.who["sub"] = "u-9"
    r = sso(client, provider)
    assert r.status_code == 401 and "kein Konto" in r.text
    # a callback without the browser's cookie is refused
    r = client.get("/login/oidc", follow_redirects=False)
    target = provider.authorize(r.headers["location"])
    client.cookies.clear()
    assert client.get(target, follow_redirects=False).status_code == 401


def test_proxy_mode_has_no_account_pages(tmp_path):
    import ipaddress
    svc = Service(make_settings(tmp_path, auth_disabled=False, auth_header="Remote-User",
                                trusted_proxies=[ipaddress.ip_network("10.0.0.1/32")]))
    with TestClient(create_app(svc), client=("10.0.0.1", 5000)) as c:
        h = {"Remote-User": "a"}
        assert c.get("/login", headers=h).status_code == 404
        assert c.get("/users", headers=h).status_code == 404
        assert c.post("/fetch", headers=h, follow_redirects=False).status_code == 303


def test_command_line_accounts(tmp_path, monkeypatch, capsys):
    import getpass

    from mailreports import __main__ as cli
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AUTH_DISABLED", "false")
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "cli-password-123")
    assert cli.main(["setup-code"]) == 0
    assert cli.main(["create-user", "ops", "--admin"]) == 0
    assert cli.main(["setup-code"]) == 1
    assert cli.main(["set-password", "ops"]) == 0
    assert cli.main(["reset-2fa", "nobody"]) == 1
    cli.main(["list-users"])
    assert "ops admin" in capsys.readouterr().out


def test_user_list_shows_second_factor_only_when_set_up(two_users):
    client, _ = two_users
    login(client, "admin", ADMIN_PW)
    client.post("/account/2fa/start", data={"csrf": csrf_of(client)})   # started, not confirmed
    row = re.search(r'>admin</a>.*?</tr>', client.get("/users").text, re.S).group(0)
    assert "aktiv" not in row


def test_link_existing_account_with_sso(tmp_path, provider):
    client, svc = app_client(tmp_path, admin_password=ADMIN_PW, oidc_issuer=ISSUER, oidc_client_id="mailreports",
                             oidc_create_users=True)
    provider.who.update({"preferred_username": "auth-admin", "sub": "u-7"})
    login(client, "admin", ADMIN_PW)
    assert "Mit SSO verknüpfen" in client.get("/account").text
    r = client.post("/account/oidc/link", data={"csrf": csrf_of(client)}, follow_redirects=False)
    r = client.get(provider.authorize(r.headers["location"]), follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/account?ok=linked"
    client.post("/logout", data={"csrf": csrf_of(client)})
    sso(client, provider)                         # signs in to the linked account, no new one
    with svc.db.connect() as con:
        assert [r[0] for r in con.execute("SELECT username FROM users")] == ["admin"]
    client.post("/account/oidc/unlink", data={"csrf": csrf_of(client)})
    with svc.db.connect() as con:
        assert con.execute("SELECT oidc_sub FROM users").fetchone()[0] == ""


def test_link_refused_when_taken(tmp_path, provider):
    client, svc = app_client(tmp_path, admin_password=ADMIN_PW, oidc_issuer=ISSUER, oidc_client_id="mailreports")
    with svc.db.connect() as con:
        accounts.create_user(con, "other", USER_PW)
        con.execute("UPDATE users SET oidc_sub = 'u-1' WHERE username = 'other'")
    login(client, "admin", ADMIN_PW)
    r = client.post("/account/oidc/link", data={"csrf": csrf_of(client)}, follow_redirects=False)
    r = client.get(provider.authorize(r.headers["location"]))
    assert r.status_code == 400 and "bereits mit einem anderen Konto" in r.text


def test_access_log_hides_codes():
    import logging

    from mailreports import main as main_module
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s"', (
        "1.2.3.4", "GET", "/oidc/callback?code=authelia_ac_secret&state=abc&iss=x"), None)
    main_module._MaskSecrets().filter(rec)
    assert "secret" not in rec.getMessage() and "abc" not in rec.getMessage() and "iss=x" in rec.getMessage()


def test_public_url_hint(tmp_path):
    client, _ = app_client(tmp_path, admin_password=ADMIN_PW)
    login(client, "admin", ADMIN_PW)
    assert "PUBLIC_URL ist nicht gesetzt" in client.get("/status").text
    (tmp_path / "b").mkdir()
    svc = Service(make_settings(tmp_path / "b", auth_disabled=False, admin_password=ADMIN_PW,
                                public_url="https://dmarc.example.org"))
    # the session cookie is HTTPS-only now, so the test client must use HTTPS
    client2 = TestClient(create_app(svc), base_url="https://testserver", headers={"accept-language": "de"})
    login(client2, "admin", ADMIN_PW)
    text = client2.get("/account").text
    assert "passt nicht zur aufgerufenen Adresse (testserver)" in text
    assert svc.settings.public_url == "https://dmarc.example.org"


def test_base_url_falls_back_to_public_url(monkeypatch):
    from mailreports import config
    monkeypatch.setenv("PUBLIC_URL", "https://dmarc.example.org/")
    assert config.load().base_url == "https://dmarc.example.org"
    monkeypatch.setenv("BASE_URL", "https://other.example.org")
    assert config.load().base_url == "https://other.example.org"


def test_sso_never_matches_by_name_or_into_admin(tmp_path, provider):
    """A provider name or address alone must not open an existing account, above all not an admin's."""
    client, svc = app_client(tmp_path, admin_password=ADMIN_PW, oidc_issuer=ISSUER, oidc_client_id="mailreports")
    with svc.db.connect() as con:
        accounts.create_user(con, "reader", USER_PW)
        con.execute("UPDATE users SET email = 'admin@example.com' WHERE username = 'admin'")
    # same username, no verified email: no account (username matching is off by default)
    assert sso(client, provider).status_code == 401
    # the admin's name and even its verified address: still no account
    provider.who.update(sub="u-2", preferred_username="admin", email="admin@example.com", email_verified=True)
    assert sso(client, provider).status_code == 401
    with svc.db.connect() as con:
        assert con.execute("SELECT oidc_sub FROM users WHERE username = 'admin'").fetchone()[0] == ""
    # with OIDC_LINK_USERNAME, ordinary accounts are matched by name
    (tmp_path / "b").mkdir()
    client2, svc2 = app_client(tmp_path / "b", admin_password=ADMIN_PW, oidc_issuer=ISSUER,
                               oidc_client_id="mailreports", oidc_link_username=True)
    with svc2.db.connect() as con:
        accounts.create_user(con, "reader", USER_PW)
    provider.who.update(sub="u-1", preferred_username="reader", email="", email_verified=False)
    assert sso(client2, provider).status_code == 303
    provider.who.update(sub="u-3", preferred_username="admin")
    client2.cookies.clear()
    assert sso(client2, provider).status_code == 401
