# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Creates the screenshots for the README (docs/screenshots/*.png).

    pip install -r requirements-browser.txt && python -m playwright install chromium
    python tools/make_screenshots.py

Generates demo reports (tools/make_demo.py), starts mailreports in English on a free
port and captures the overview, a domain, a report and a phone view.
"""
from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "screenshots"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> None:
    import uvicorn
    from playwright.sync_api import sync_playwright

    from mailreports.config import Settings
    from mailreports.ingest import Outcome, ingest_payload
    from mailreports.main import create_app
    from mailreports.parsing import Payload
    from mailreports.service import Service

    tmp = Path(tempfile.mkdtemp(prefix="mailreports-shots-"))
    subprocess.run([sys.executable, str(ROOT / "tools" / "make_demo.py"), str(tmp / "files"), "--days", "60"],
                   check=True)
    svc = Service(Settings(data_dir=tmp / "data", sources_file=str(tmp / "files" / "sources.toml"),
                           dns_lookups=False, background_tasks=False, default_language="en",
                           timezone="Europe/Berlin"))
    total = Outcome()
    for f in sorted((tmp / "files").glob("*.gz")):
        total.merge(ingest_payload(svc.db, Payload(f.name, f.read_bytes())))
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(svc), port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.1)
    base = f"http://127.0.0.1:{port}"
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for scheme in ("dark", "light"):
            page = browser.new_page(viewport={"width": 1280, "height": 860}, color_scheme=scheme,
                                    device_scale_factor=1)
            page.goto(f"{base}/?days=30")
            page.screenshot(path=OUT / f"overview-{scheme}.png")
            if scheme == "dark":
                page.goto(f"{base}/domain/example.org?days=30")
                page.screenshot(path=OUT / "domain.png", full_page=False)
                page.goto(f"{base}/reports?days=30&failed=1&domain=example.org")
                page.click("table a")
                page.screenshot(path=OUT / "report.png")
                page.goto(f"{base}/tls?days=30")
                page.screenshot(path=OUT / "tls.png")
            page.close()
        phone = browser.new_page(viewport={"width": 390, "height": 844}, color_scheme="light",
                                 device_scale_factor=2, is_mobile=True)
        phone.goto(f"{base}/?days=30")
        phone.screenshot(path=OUT / "mobile-light.png")
        browser.close()
    server.should_exit = True
    print(f"screenshots written to {OUT}")


if __name__ == "__main__":
    main()
