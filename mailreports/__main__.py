# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Command line: python -m mailreports import FILE... | fetch | check"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .ingest import Outcome, ingest_mail, ingest_payload
from .parsing import Payload
from .service import Service


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mailreports")
    sub = parser.add_subparsers(dest="cmd", required=True)
    imp = sub.add_parser("import", help="import report files (.xml, .json, .gz, .zip), saved mails (.eml) or folders")
    imp.add_argument("files", nargs="+", type=Path)
    sub.add_parser("fetch", help="fetch the IMAP mailbox once")
    sub.add_parser("check", help="test the IMAP login and show the settings")
    args = parser.parse_args(argv)

    svc = Service()
    if args.cmd == "import":
        total = Outcome()
        paths = [p for arg in args.files for p in (sorted(arg.iterdir()) if arg.is_dir() else [arg]) if p.is_file()]
        for path in paths:
            if path.suffix.lower() in (".toml", ".txt", ".md"):
                continue
            data = path.read_bytes()
            out = ingest_mail(svc.db, data) if path.suffix.lower() == ".eml" else \
                ingest_payload(svc.db, Payload(path.name, data))
            total.merge(out)
            print(f"{path}: {len(out.new_dmarc)} DMARC, {len(out.new_tls)} TLS, {out.duplicates} duplicate"
                  + (f", errors: {'; '.join(out.errors)}" if out.errors else ""))
        svc.after_import(total)
        return 1 if total.errors and not total.found_any else 0
    if args.cmd == "fetch":
        if not svc.settings.imap_enabled:
            print("IMAP is not configured (IMAP_HOST, IMAP_USER)", file=sys.stderr)
            return 2
        result = svc.run_once()
        if result is None:
            return 1
        o = result.outcome
        print(f"{result.mails} mails, {len(o.new_dmarc)} new DMARC, {len(o.new_tls)} new TLS, "
              f"{o.duplicates} duplicates, {len(o.errors)} errors")
        if result.error:
            print(result.error, file=sys.stderr)
            return 1
        return 0
    if args.cmd == "check":
        from .fetch import connect
        s = svc.settings
        print(f"data: {s.db_path}\nsources: {len(svc.sources)} from {s.sources_file or '-'}\n"
              f"geoip: city={s.geoip_city_db or '-'} country={s.geoip_country_db or '-'} asn={s.geoip_asn_db or '-'}\n"
              f"pushover: {'on' if s.pushover_enabled else 'off'}")
        if not s.imap_enabled:
            print("imap: not configured")
            return 0
        try:
            conn = connect(s)
            typ, data = conn.select(f'"{s.imap_folder}"', readonly=True)
            print(f"imap: login ok, {s.imap_folder}: {data[0].decode() if typ == 'OK' else data} mails")
            conn.logout()
        except Exception as exc:
            print(f"imap: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
