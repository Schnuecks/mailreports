# Entwicklung

## Lokal starten

Du brauchst Python 3.15 (3.14 geht auch).

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
```

Mit Beispieldaten starten – 45 Tage Berichte für `example.org` und `example.net`, nur mit
Dokumentationsadressen:

```bash
python tools/make_demo.py /tmp/demo
export DATA_DIR=/tmp/demo-data SOURCES_FILE=/tmp/demo/sources.toml DNS_LOOKUPS=false
python -m mailreports import /tmp/demo
python -m uvicorn --factory mailreports.main:create_app --port 8080
```

Ohne `IMAP_HOST` wird nichts abgerufen; Berichte kommen dann nur über den Import oder das
Hochladen auf der Statusseite.

## Prüfungen

```bash
python -m ruff check                  # Linter
python -m pytest -q                   # Tests, ohne Netzwerkzugriff
python tools/i18n_extract.py          # Übersetzungen, muss 0 fehlend melden
```

Die CI führt dieselben Prüfungen aus und baut bei Pull-Requests und Versions-Tags das Image
für amd64 und arm64, startet es einmal und prüft es mit Trivy.

## Übersetzungen

Die deutschen Texte im Code sind zugleich die Schlüssel. `mailreports/locales/en.json`
ordnet ihnen das Englische zu; fehlt ein Eintrag, erscheint der deutsche Text. Platzhalter
stehen in geschweiften Klammern und müssen auch in der Übersetzung vorkommen (ein Test
prüft das):

```python
_("{n} Mails", n=3)
ngettext("{n} Mail", "{n} Mails", n)
```

`tools/i18n_extract.py --keys` gibt alle Schlüssel als JSON aus, um eine neue Sprache
anzufangen.

## Screenshots

Die Bilder in `docs/screenshots/` entstehen mit Playwright aus den Beispieldaten:

```bash
pip install -r requirements-browser.txt && python -m playwright install chromium
python tools/make_screenshots.py
```

## Regeln für die Seiten

- Keine eingebetteten Skripte oder Styles: Die Content Security Policy blockiert sie (ein
  Test prüft `style="`). Diagramme sind eingebettetes SVG mit Attributen.
- Nichts von Dritten: Schrift ist die Systemschrift, Symbole sind SVG in `static/`.
- Text aus Berichten ist nicht vertrauenswürdig und wird von den Templates immer maskiert.

## Releases

Änderungen laufen über einen Pull-Request. Die Versionsnummer kommt schon in den
Pull-Request: `__version__` in `mailreports/__init__.py` und die Überschrift in
`CHANGELOG.md`. Nach dem Merge baut der Tag `vX.Y.Z` auf dem Merge-Commit das Image und lädt
es hoch; die CI prüft, dass der Tag zu `__version__` passt.
