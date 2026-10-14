# Development

## Running locally

You need Python 3.15 (3.14 works as well).

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
```

Start it with demo data – 45 days of reports for `example.org` and `example.net`, using
documentation addresses only:

```bash
python tools/make_demo.py /tmp/demo
export DATA_DIR=/tmp/demo-data SOURCES_FILE=/tmp/demo/sources.toml DNS_LOOKUPS=false
python -m mailreports import /tmp/demo
python -m uvicorn --factory mailreports.main:create_app --port 8080
```

Without `IMAP_HOST` nothing is fetched; reports come only from the import or the upload on
the status page.

## Checks

```bash
python -m ruff check                  # linter
python -m pytest -q                   # tests, no network access needed
python tools/i18n_extract.py          # translations, must report 0 missing
```

CI runs the same checks and, for pull requests and version tags, builds the image for amd64
and arm64, starts it once and scans it with Trivy.

## Translations

The German texts in the code are also the keys. `mailreports/locales/en.json` maps them to
English; a missing entry shows the German text. Placeholders are in curly braces and must
appear in the translation as well (a test checks this):

```python
_("{n} Mails", n=3)
ngettext("{n} Mail", "{n} Mails", n)
```

`tools/i18n_extract.py --keys` prints all keys as JSON to start a new language.

## Screenshots

The images in `docs/screenshots/` are created with Playwright from the demo data:

```bash
pip install -r requirements-browser.txt && python -m playwright install chromium
python tools/make_screenshots.py
```

## Rules for the pages

- No inline scripts or styles: the Content Security Policy blocks them (a test checks
  `style="`). Charts are inline SVG with attributes.
- Nothing from third parties: fonts are the system font, icons are SVG in `static/`.
- Text from reports is untrusted input and is always escaped by the templates.

## Releases

Changes go through a pull request. The version number is set in the pull request:
`__version__` in `mailreports/__init__.py` and the heading in `CHANGELOG.md`. After the merge,
the tag `vX.Y.Z` on the merge commit builds and uploads the image; CI checks that the tag
matches `__version__`.
