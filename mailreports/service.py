# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Everything the app needs at runtime, plus the background fetch loop."""
from __future__ import annotations

import logging
import threading

from . import config, enrich, fetch, notify
from .db import Database
from .ingest import Outcome
from .sources import load_sources

log = logging.getLogger(__name__)


class Service:
    def __init__(self, settings: config.Settings | None = None):
        self.settings = settings or config.load()
        if self.settings.auth_header and not self.settings.trusted_proxies:
            # Without it anyone who reaches the port could send the header and sign in as anybody
            raise SystemExit("AUTH_HEADER needs TRUSTED_PROXIES: set it to the address of your reverse proxy "
                             "(for a proxy with network_mode: host, the gateway of the proxy network).")
        self.db = Database(self.settings.db_path)
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

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                log.exception("fetch run failed")
            self._wake.wait(self.settings.fetch_interval)
            self._wake.clear()

    def start(self) -> None:
        if self._thread or not self.settings.background_tasks or not self.settings.imap_enabled:
            return
        self._thread = threading.Thread(target=self._loop, name="fetch", daemon=True)
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
