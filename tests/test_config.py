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
