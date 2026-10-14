# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Command line: python -m mailreports import | fetch | check | create-user | set-password | reset-2fa | ..."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import accounts
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
    sub.add_parser("hash-password", help="read a password and print its Argon2 hash for ADMIN_PASSWORD")
    cu = sub.add_parser("create-user", help="create an account (asks for the password)")
    cu.add_argument("username")
    cu.add_argument("--admin", action="store_true", help="with admin rights")
    sp = sub.add_parser("set-password", help="set a new password for an account (ends its sessions)")
    sp.add_argument("username")
    r2 = sub.add_parser("reset-2fa", help="remove authenticator app, passkeys and recovery codes of an account")
    r2.add_argument("username")
    sub.add_parser("list-users", help="list the accounts")
    sub.add_parser("setup-code", help="show the setup code for the first account")
    args = parser.parse_args(argv)

    if args.cmd == "hash-password":
        password = _ask_password()
        if password is None:
            return 2
        print(accounts.hash_password(password))
        return 0

    svc = Service()
    if args.cmd in ("create-user", "set-password", "reset-2fa", "list-users", "setup-code"):
        return _accounts_command(svc, args)
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


def _ask_password() -> str | None:
    import getpass
    first = getpass.getpass("Password: ")
    problem = accounts.password_problem(first)
    if problem:
        print("The password must have 10 to 1024 characters.", file=sys.stderr)
        return None
    if getpass.getpass("Repeat: ") != first:
        print("The passwords differ.", file=sys.stderr)
        return None
    return first


def _accounts_command(svc: Service, args) -> int:
    with svc.db.connect() as con:
        if args.cmd == "list-users":
            for u in con.execute("SELECT * FROM users ORDER BY username COLLATE NOCASE"):
                flags = [f for f, on in (("admin", u["is_admin"]), ("disabled", not u["enabled"]),
                                         ("2fa", u["totp_enabled"])) if on]
                print(u["username"], " ".join(flags))
            return 0
        if args.cmd == "setup-code":
            if accounts.has_users(con):
                print("There are accounts already; no setup code needed.")
                return 1
            print(accounts.setup_code(con))
            return 0
        user = con.execute("SELECT * FROM users WHERE username = ?", (args.username,)).fetchone()
        if args.cmd == "create-user":
            if user is not None or accounts.username_problem(args.username):
                print("This username exists already or is not allowed.", file=sys.stderr)
                return 1
            password = _ask_password()
            if password is None:
                return 2
            accounts.create_user(con, args.username, password, is_admin=args.admin)
            accounts.clear_setup_code(con)
            print(f"Account {args.username} created.")
            return 0
        if user is None:
            print(f"There is no account {args.username}.", file=sys.stderr)
            return 1
        if args.cmd == "set-password":
            password = _ask_password()
            if password is None:
                return 2
            accounts.set_password(con, user["id"], password)
            print("Password set; all sessions of this account were ended.")
            return 0
        accounts.reset_second_factors(con, user["id"])
        print("Authenticator app, passkeys and recovery codes removed.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
