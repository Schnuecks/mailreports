# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Everything the app needs at runtime, plus the background fetch loop."""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime

from . import accounts, config, enrich, fetch, notify, secretbox, web
from .db import Database
from .ingest import Outcome
from .sources import load_sources

log = logging.getLogger(__name__)


class Service:
    def __init__(self, settings: config.Settings | None = None):
        self.settings = settings or config.load()
        s = self.settings
        if s.auth_header and not s.trusted_proxies:
            # Without it anyone who reaches the port could send the header and sign in as anybody
            raise SystemExit("AUTH_HEADER needs TRUSTED_PROXIES: set it to the address of your reverse proxy "
                             "(for a proxy with network_mode: host, the gateway of the proxy network).")
        if s.auth_disabled and not s.auth_header:
            log.warning("AUTH_DISABLED is set: everybody who reaches the port can see all reports.")
        if s.oidc_issuer and not s.oidc_issuer.startswith("https://"):
            raise SystemExit("OIDC_ISSUER must be an https:// address.")
        self.limiter = accounts.LoginLimiter()
        self.db = Database(self.settings.db_path)
        if s.accounts_enabled:
            self._prepare_accounts()
        self.sources = load_sources(self.settings.sources_file)
        self.geo = enrich.GeoIP(self.settings)
        for net in self.settings.trusted_proxies:
            if net.num_addresses > 1:
                log.warning("TRUSTED_PROXIES contains the whole network %s: every host in it can send the "
                            "login header. Prefer the proxy's single address.", net)
        self._run_lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _prepare_accounts(self) -> None:
        s = self.settings
        with self.db.connect() as con:
            secretbox.migrate(con, s.secret_key)
            if accounts.has_users(con):
                return
            if s.admin_password:
                # First account from the configuration (also the upgrade path from 0.1.x)
                if s.admin_password.startswith("$argon2"):
                    accounts.create_user(con, s.admin_username, "", is_admin=True, password_hash=s.admin_password)
                else:
                    accounts.create_user(con, s.admin_username, s.admin_password, is_admin=True)
                log.warning("Account %s created from ADMIN_PASSWORD.", s.admin_username)
                return
            code = accounts.setup_code(con)
        log.warning("No account yet. Open the page and create the first one with the setup code %s", code)

    # ------------------------------------------------------------ one run

    def after_import(self, outcome: Outcome) -> None:
        """Enrich new IPs and send notifications for freshly stored reports."""
        try:
            enrich.enrich(self.db, self.settings, self.geo)
        except Exception:  # enrichment is optional, never block storing reports
            log.exception("IP enrichment failed")
        if outcome.new_dmarc or outcome.new_tls:
            notify.notify(self.db, self.settings, self.sources, outcome.new_dmarc, outcome.new_tls)

    def run_once(self) -> fetch.FetchResult | None:
        if not self.settings.imap_enabled:
            return None
        if not self._run_lock.acquire(blocking=False):
            return None   # a run is already in progress
        try:
            result = fetch.fetch(self.db, self.settings)
            fetch.record_run(self.db, result)
            if result.error:
                log.warning("%s", fetch.describe_error(result.error))
            else:
                o = result.outcome
                log.info("fetch: %d mails, %d new DMARC, %d new TLS, %d duplicates, %d errors",
                         result.mails, len(o.new_dmarc), len(o.new_tls), o.duplicates, len(o.errors))
            self.after_import(result.outcome)
            return result
        finally:
            self._run_lock.release()

    @property
    def running(self) -> bool:
        return self._run_lock.locked()

    # ------------------------------------------------------------ loop

    def periodic(self) -> None:
        """Daily jobs: deleting old data; the weekly summary."""
        now = int(time.time())
        s = self.settings
        if s.digest == "weekly" and s.notify_enabled:
            local = datetime.fromtimestamp(now, web.zone(s.timezone))
            week = local.strftime("%G-W%V")
            if local.weekday() == s.digest_weekday and local.hour >= 8 and self.db.get_meta("last_digest") != week:
                if notify.send_digest(self.db, s, self.sources, web.zone(s.timezone)):
                    self.db.set_meta("last_digest", week)
        if now - int(self.db.get_meta("last_housekeeping", "0") or 0) >= 86400:
            removed = self.db.housekeeping(self.settings.retention_days)
            self.db.set_meta("last_housekeeping", str(now))
            if removed["dmarc"] or removed["tls"]:
                log.info("housekeeping: %d DMARC and %d TLS reports older than %d days deleted",
                         removed["dmarc"], removed["tls"], self.settings.retention_days)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                log.exception("fetch run failed")
            try:
                self.periodic()
            except Exception:
                log.exception("periodic jobs failed")
            self._wake.wait(self.settings.fetch_interval)
            self._wake.clear()

    def start(self) -> None:
        if self._thread or not self.settings.background_tasks:
            return
        self._thread = threading.Thread(target=self._loop, name="background", daemon=True)
        self._thread.start()

    def trigger(self) -> None:
        """Fetch now instead of waiting for the interval."""
        if self._thread:
            self._wake.set()
        else:
            threading.Thread(target=self.run_once, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
