# Contributing to mailreports

Thanks for your interest! Bug reports, ideas and pull requests are welcome.

## Reporting problems

Use the issue forms: **Bug report** or **Feature request**. For bugs, please add the
container log. German is fine too. If a report file is not read correctly, attach it with
your own domains and IP addresses replaced.

Security problems go to **Security → Report a vulnerability** instead, see
[SECURITY.md](SECURITY.md).

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m ruff check
python -m pytest -q
python tools/i18n_extract.py          # must report 0 missing
```

Run it locally with demo data:

```bash
python tools/make_demo.py /tmp/demo
export DATA_DIR=/tmp/demo-data SOURCES_FILE=/tmp/demo/sources.toml DNS_LOOKUPS=false
python -m mailreports import /tmp/demo
python -m uvicorn --factory mailreports.main:create_app --port 8080
```

## Pull requests

1. Open an issue first for larger changes, so we can agree on the approach.
2. Tests, linter and translation check must pass.
3. Texts in the code are German and serve as keys; add the English translation to
   `mailreports/locales/en.json`.
4. Nothing from third parties in the page, and no inline scripts or styles (the Content
   Security Policy blocks them).
5. Update `docs/en` and `docs/de` if users notice the change, and add a line under
   "Unreleased" in `CHANGELOG.md`.

## Code layout

| Path | Contents |
|---|---|
| `mailreports/config.py` | Settings from the environment, `*_FILE` support |
| `mailreports/parsing.py` | Unpacking attachments, DMARC XML and TLS JSON parser |
| `mailreports/db.py` | SQLite schema and storing |
| `mailreports/ingest.py` | Mail or file → stored reports |
| `mailreports/fetch.py` | IMAP fetch, flagging and moving |
| `mailreports/sources.py` | Known senders and classification |
| `mailreports/enrich.py` | Reverse DNS and GeoIP |
| `mailreports/explain.py` | Plain-language explanations |
| `mailreports/notify.py` | Pushover notifications |
| `mailreports/queries.py` | Queries for the pages |
| `mailreports/main.py`, `web.py` | Web app, access check, templates and charts |
| `mailreports/templates/`, `static/` | Pages, styles, icon |
| `tools/make_demo.py` | Demo reports |
| `tools/i18n_extract.py` | Translation check |

## License

By contributing you agree that your contribution is released under the
[GNU Affero General Public License, version 3 or later](LICENSE).
