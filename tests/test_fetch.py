# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

from mailreports import fetch
from tests.conftest import DMARC_XML, TLS_JSON, gz, make_settings
from tests.test_ingest import mail


class FakeIMAP:
    def __init__(self, messages, caps=("IMAP4REV1", "MOVE", "UIDPLUS")):
        self.capabilities = caps
        self.folders = {"INBOX": dict(messages)}
        self.flags: dict[bytes, set] = {}
        self.calls = []

    def select(self, folder, readonly=False):
        name = folder.strip('"')
        return ("OK", [str(len(self.folders.get(name, {}))).encode()]) if name in self.folders else ("NO", [b"no"])

    def create(self, folder):
        self.folders[folder.strip('"')] = {}
        return "OK", [b""]

    def subscribe(self, folder):
        return "OK", [b""]

    def uid(self, cmd, *args):
        self.calls.append((cmd, args))
        inbox = self.folders["INBOX"]
        if cmd == "SEARCH":
            uids = [u for u in inbox if not self.flags.get(u, set()) & {fetch.KW_DONE, fetch.KW_ERROR}]
            return "OK", [b" ".join(uids)]
        if cmd == "FETCH":
            return "OK", [(b"1 (BODY[] {n}", inbox[args[0]]), b")"]
        if cmd == "MOVE":
            self.folders[args[1].strip('"')][args[0]] = inbox.pop(args[0])
            return "OK", [b""]
        if cmd == "STORE":
            for flag in args[2].strip("()").split():
                self.flags.setdefault(args[0], set()).add(flag)
            return "OK", [b""]
        raise AssertionError(cmd)

    def response(self, code):
        return code, [b"42"]

    def expunge(self):
        return "OK", [b""]

    def logout(self):
        return "BYE", [b""]


def test_fetch_flags_mails(service, monkeypatch):
    fake = FakeIMAP({b"1": mail(("r.xml.gz", gz(DMARC_XML), "application/gzip")),
                     b"2": mail(("t.json", TLS_JSON, "application/json")),
                     b"3": mail()})
    monkeypatch.setattr(fetch, "connect", lambda s: fake)
    service.settings.imap_host, service.settings.imap_user = "imap.test", "u"
    result = service.run_once()
    assert result.error == ""
    assert result.mails == 3
    assert len(result.outcome.new_dmarc) == 1 and len(result.outcome.new_tls) == 1
    assert fetch.KW_DONE in fake.flags[b"1"] and r"\Seen" in fake.flags[b"1"]
    assert fetch.KW_ERROR in fake.flags[b"3"]
    # second run: nothing left to do
    assert service.run_once().mails == 0
    assert service.db.get_meta("last_fetch_ok")


def test_fetch_moves_to_folders(tmp_path, monkeypatch):
    from mailreports.service import Service
    svc = Service(make_settings(tmp_path, imap_host="imap.test", imap_user="u",
                                imap_move_to="Reports/Done", imap_error_folder="Reports/Error"))
    fake = FakeIMAP({b"1": mail(("r.xml", DMARC_XML, "text/xml")), b"2": mail()})
    monkeypatch.setattr(fetch, "connect", lambda s: fake)
    svc.run_once()
    assert list(fake.folders["Reports/Done"]) == [b"1"]
    assert list(fake.folders["Reports/Error"]) == [b"2"]
    assert fake.folders["INBOX"] == {}


def test_connection_error_is_recorded(service, monkeypatch):
    def boom(settings):
        raise OSError("connection refused")
    monkeypatch.setattr(fetch, "connect", boom)
    service.settings.imap_host, service.settings.imap_user = "imap.test", "u"
    result = service.run_once()
    assert "connection refused" in result.error
    assert "connection refused" in service.db.get_meta("last_fetch_error")


@pytest.mark.parametrize("text", ["LOGIN user secret failed"])
def test_describe_error_hides_password(text):
    assert "secret" not in fetch.describe_error(text)


def test_readonly_changes_nothing(tmp_path, monkeypatch):
    from mailreports.service import Service
    svc = Service(make_settings(tmp_path, imap_host="imap.test", imap_user="u", imap_readonly=True,
                                imap_move_to="Done"))
    fake = FakeIMAP({b"1": mail(("r.xml", DMARC_XML, "text/xml")), b"2": mail()})
    monkeypatch.setattr(fetch, "connect", lambda s: fake)
    first = svc.run_once()
    assert first.mails == 2 and len(first.outcome.new_dmarc) == 1
    assert {c[0] for c in fake.calls} <= {"SEARCH", "FETCH"}
    assert "Done" not in fake.folders and not fake.flags
    assert svc.run_once().mails == 0          # remembered in the database
    fake.folders["INBOX"][b"3"] = mail(("t.json", TLS_JSON, "application/json"))
    third = svc.run_once()
    assert third.mails == 1 and len(third.outcome.new_tls) == 1
