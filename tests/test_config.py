# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

from mailreports import config


def test_file_variables(tmp_path, monkeypatch):
    secret = tmp_path / "pw.txt"
    secret.write_text("s3cret\n", encoding="utf-8")
    monkeypatch.setenv("IMAP_PASSWORD", "ignored")
    monkeypatch.setenv("IMAP_PASSWORD_FILE", str(secret))
    monkeypatch.setenv("PUSHOVER_TOKEN_FILE", str(secret))
    monkeypatch.setenv("TRUSTED_PROXIES", "172.18.0.0/16, 10.0.0.1")
    s = config.load()
    assert s.imap_password == "s3cret"
    assert s.pushover_token == "s3cret"
    assert len(s.trusted_proxies) == 2


def test_missing_file_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("IMAP_PASSWORD_FILE", "/does/not/exist")
    with pytest.raises(SystemExit, match="IMAP_PASSWORD_FILE"):
        config.load()


def test_starttls_default_port(monkeypatch):
    monkeypatch.setenv("IMAP_SECURITY", "starttls")
    assert config.load().imap_port == 143


def test_warns_about_wide_trusted_network(tmp_path, caplog):
    import ipaddress

    from mailreports.service import Service
    from tests.conftest import make_settings
    Service(make_settings(tmp_path, trusted_proxies=[ipaddress.ip_network("172.20.1.0/24")]))
    assert "whole network 172.20.1.0/24" in caplog.text
    caplog.clear()
    Service(make_settings(tmp_path, trusted_proxies=[ipaddress.ip_network("172.20.1.1/32")]))
    assert "whole network" not in caplog.text


def test_theme(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from mailreports.main import create_app
    from mailreports.service import Service
    from tests.conftest import make_settings
    monkeypatch.setenv("THEME", "Olive")
    assert config.load().theme == "olive"
    monkeypatch.setenv("THEME", "pink")
    with pytest.raises(SystemExit):
        config.load()
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    html = TestClient(create_app(Service(make_settings(tmp_path / "a", theme="olive")))).get("/").text
    assert 'data-theme="olive"' in html and "/static/icon-olive.svg" in html
    html = TestClient(create_app(Service(make_settings(tmp_path / "b")))).get("/").text
    assert "data-theme" not in html and 'src="/static/icon.svg"' in html
