# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Unpacking and parsing of DMARC aggregate reports (RFC 7489) and SMTP TLS reports (RFC 8460).

Reports arrive as mail attachments, usually compressed (.gz, .zip), sometimes plain.
The content decides how a file is read, not its name or MIME type: senders label
the same thing as application/zip, application/gzip, application/octet-stream ...
"""
from __future__ import annotations

import email
import email.policy
import gzip
import io
import ipaddress
import json
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage

from defusedxml import ElementTree

MAX_UNPACKED = 50 * 1024 * 1024    # unpacked bytes per mail (or uploaded file), against zip/gzip bombs
MAX_NESTING = 3
MAX_MEMBERS = 20                    # files per zip archive; real reports have one


class ReportError(ValueError):
    """The data is not a usable report."""


@dataclass
class Payload:
    name: str
    data: bytes


@dataclass
class DmarcRecord:
    source_ip: str
    count: int
    disposition: str
    dkim_eval: str
    spf_eval: str
    header_from: str
    envelope_from: str = ""
    envelope_to: str = ""
    reasons: list[dict] = field(default_factory=list)
    dkim: list[dict] = field(default_factory=list)
    spf: list[dict] = field(default_factory=list)

    @property
    def dmarc_pass(self) -> bool:
        return self.dkim_eval == "pass" or self.spf_eval == "pass"


@dataclass
class DmarcReport:
    org_name: str
    org_email: str
    report_id: str
    date_begin: int
    date_end: int
    domain: str
    policy: dict
    records: list[DmarcRecord]
    errors: list[str] = field(default_factory=list)


@dataclass
class TlsFailure:
    result_type: str
    failed_session_count: int
    sending_mta_ip: str = ""
    receiving_mx_hostname: str = ""
    receiving_mx_helo: str = ""
    receiving_ip: str = ""
    additional_information: str = ""
    failure_reason_code: str = ""


@dataclass
class TlsPolicy:
    policy_type: str
    policy_domain: str
    policy_strings: list[str]
    mx_hosts: list[str]
    success: int
    failure: int
    failures: list[TlsFailure]


@dataclass
class TlsReport:
    org_name: str
    report_id: str
    date_begin: int
    date_end: int
    contact: str
    policies: list[TlsPolicy]


# ---------------------------------------------------------------- unpacking

class Budget:
    """Unpacked bytes still allowed. Shared by all attachments of one mail, so many small
    archives cannot add up to more than MAX_UNPACKED."""

    def __init__(self, limit: int | None = None):
        self.remaining = MAX_UNPACKED if limit is None else limit

    def take(self, n: int) -> None:
        self.remaining -= n
        if self.remaining < 0:
            raise ReportError("unpacked content too large")


def _gunzip(data: bytes, budget: Budget) -> bytes:
    stream = gzip.GzipFile(fileobj=io.BytesIO(data))
    try:
        out = stream.read(budget.remaining + 1)
    except (OSError, EOFError, zlib.error) as exc:
        raise ReportError(f"broken gzip data: {exc}") from exc
    budget.take(len(out))
    return out


def _unzip(data: bytes, budget: Budget) -> list[Payload]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ReportError(f"broken zip archive: {exc}") from exc
    members = [info for info in archive.infolist() if not info.is_dir()]
    if len(members) > MAX_MEMBERS:
        raise ReportError(f"zip archive with {len(members)} files")
    if sum(info.file_size for info in members) > budget.remaining:
        raise ReportError("unpacked content too large")
    out = []
    for info in members:
        try:
            with archive.open(info) as member:
                content = member.read(budget.remaining + 1)
        except (zipfile.BadZipFile, RuntimeError, OSError, zlib.error) as exc:
            raise ReportError(f"broken zip member {info.filename}: {exc}") from exc
        budget.take(len(content))
        out.append(Payload(info.filename, content))
    return out


def unpack(payload: Payload, depth: int = 0, budget: Budget | None = None) -> list[Payload]:
    """Decompress until plain XML or JSON remains."""
    budget = budget or Budget()
    data = payload.data
    if depth > MAX_NESTING:
        raise ReportError("too deeply nested archive")
    if data[:4] == b"PK\x03\x04":
        result = []
        for member in _unzip(data, budget):
            result.extend(unpack(member, depth + 1, budget))
        return result
    if data[:2] == b"\x1f\x8b":
        name = payload.name[:-3] if payload.name.lower().endswith(".gz") else payload.name
        return unpack(Payload(name, _gunzip(data, budget)), depth + 1, budget)
    return [payload]


def kind_of(data: bytes) -> str | None:
    """'dmarc', 'tls' or None, judged by the first characters."""
    head = data[:512].lstrip(b"\xef\xbb\xbf \t\r\n")
    if head.startswith(b"<"):
        return "dmarc"
    if head.startswith(b"{"):
        return "tls"
    return None


_REPORT_TYPES = (
    "application/zip", "application/x-zip", "application/x-zip-compressed",
    "application/gzip", "application/x-gzip", "application/octet-stream",
    "application/xml", "text/xml", "application/json",
    "application/tlsrpt+gzip", "application/tlsrpt+json",
)


def attachments(msg: EmailMessage) -> list[Payload]:
    """All parts of a mail that may contain a report."""
    found = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type().lower()
        name = part.get_filename() or ""
        lname = name.lower()
        if ctype not in _REPORT_TYPES and not lname.endswith((".xml", ".gz", ".zip", ".json")):
            continue
        data = part.get_payload(decode=True)
        if data:
            found.append(Payload(name or ctype, data))
    return found


def parse_mail(raw: bytes) -> EmailMessage:
    return email.message_from_bytes(raw, policy=email.policy.default)


# ---------------------------------------------------------------- DMARC

def _strip_ns(root) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def _text(el, path: str, default: str = "") -> str:
    if el is None:
        return default
    found = el.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def _int(value: str, default: int = 0) -> int:
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return default


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value.strip()


def parse_dmarc(data: bytes) -> DmarcReport:
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        raise ReportError(f"invalid XML: {exc}") from exc
    except Exception as exc:  # defusedxml raises its own types for forbidden constructs
        raise ReportError(f"rejected XML: {exc.__class__.__name__}") from exc
    _strip_ns(root)
    if root.tag != "feedback":
        raise ReportError(f"not a DMARC report (root element <{root.tag}>)")
    meta = root.find("report_metadata")
    pub = root.find("policy_published")
    org = _text(meta, "org_name")
    report_id = _text(meta, "report_id")
    domain = _text(pub, "domain").lower().rstrip(".")
    if not report_id or not domain:
        raise ReportError("DMARC report without report_id or domain")
    policy = {key: _text(pub, key) for key in ("adkim", "aspf", "p", "sp", "pct", "fo", "np")}
    records = []
    for rec in root.findall("record"):
        row = rec.find("row")
        ev = row.find("policy_evaluated") if row is not None else None
        ids = rec.find("identifiers")
        auth = rec.find("auth_results")
        records.append(DmarcRecord(
            source_ip=_ip(_text(row, "source_ip")),
            count=_int(_text(row, "count"), 1),
            disposition=_text(ev, "disposition", "none").lower(),
            dkim_eval=_text(ev, "dkim").lower(),
            spf_eval=_text(ev, "spf").lower(),
            header_from=_text(ids, "header_from").lower(),
            envelope_from=_text(ids, "envelope_from").lower(),
            envelope_to=_text(ids, "envelope_to").lower(),
            reasons=[{"type": _text(r, "type"), "comment": _text(r, "comment")}
                     for r in (ev.findall("reason") if ev is not None else [])],
            dkim=[{"domain": _text(d, "domain").lower(), "selector": _text(d, "selector"),
                   "result": _text(d, "result").lower(), "human_result": _text(d, "human_result")}
                  for d in (auth.findall("dkim") if auth is not None else [])],
            spf=[{"domain": _text(s, "domain").lower(), "scope": _text(s, "scope"),
                  "result": _text(s, "result").lower()}
                 for s in (auth.findall("spf") if auth is not None else [])],
        ))
    return DmarcReport(
        org_name=org or "?",
        org_email=_text(meta, "email"),
        report_id=report_id,
        date_begin=_int(_text(meta, "date_range/begin")),
        date_end=_int(_text(meta, "date_range/end")),
        domain=domain,
        policy=policy,
        records=records,
        errors=[e.text.strip() for e in (meta.findall("error") if meta is not None else []) if e.text],
    )


# ---------------------------------------------------------------- SMTP TLS reporting

def _timestamp(value) -> int:
    if not value:
        return 0
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp())


def _list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_tls(data: bytes) -> TlsReport:
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReportError(f"invalid JSON: {exc}") from exc
    if not isinstance(doc, dict) or "policies" not in doc:
        raise ReportError("not an SMTP TLS report (no policies)")
    report_id = str(doc.get("report-id") or "").strip()
    if not report_id:
        raise ReportError("TLS report without report-id")
    rng = doc.get("date-range") or {}
    policies = []
    for item in _list(doc.get("policies")):
        if not isinstance(item, dict):
            continue
        pol = item.get("policy") or {}
        summary = item.get("summary") or {}
        failures = []
        for f in _list(item.get("failure-details")):
            if not isinstance(f, dict):
                continue
            failures.append(TlsFailure(
                result_type=str(f.get("result-type") or "unknown").lower(),
                failed_session_count=_int(str(f.get("failed-session-count", 0))),
                sending_mta_ip=_ip(str(f.get("sending-mta-ip") or "")),
                receiving_mx_hostname=str(f.get("receiving-mx-hostname") or "").rstrip(".").lower(),
                receiving_mx_helo=str(f.get("receiving-mx-helo") or ""),
                receiving_ip=_ip(str(f.get("receiving-ip") or "")),
                additional_information=str(f.get("additional-information") or ""),
                failure_reason_code=str(f.get("failure-reason-code") or ""),
            ))
        policies.append(TlsPolicy(
            policy_type=str(pol.get("policy-type") or "").lower(),
            policy_domain=str(pol.get("policy-domain") or "").rstrip(".").lower(),
            policy_strings=[str(s) for s in _list(pol.get("policy-string"))],
            mx_hosts=[str(m).rstrip(".").lower() for m in _list(pol.get("mx-host"))],
            success=_int(str(summary.get("total-successful-session-count", 0))),
            failure=_int(str(summary.get("total-failure-session-count", 0))),
            failures=failures,
        ))
    contact = doc.get("contact-info") or ""
    return TlsReport(
        org_name=str(doc.get("organization-name") or "?").strip(),
        report_id=report_id,
        date_begin=_timestamp(rng.get("start-datetime")),
        date_end=_timestamp(rng.get("end-datetime")),
        contact=str(contact),
        policies=policies,
    )
