<p align="center"><img src="docs/logo.svg" width="96" alt="mailreports"></p>

# mailreports

[English](README.md) · **Deutsch**

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.15-3776AB?logo=python&logoColor=white" alt="Python 3.15">
  <a href="https://github.com/Schnuecks/mailreports/pkgs/container/mailreports"><img src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white" alt="Docker ready"></a>
  <img src="https://img.shields.io/badge/platform-amd64%20%7C%20arm64-E4572E" alt="Platform amd64 | arm64">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-4C9A2A" alt="License AGPL-3.0"></a>
</p>

Sammelt **DMARC-Aggregate-Berichte** und **SMTP-TLS-Berichte** aus einem IMAP-Postfach und
erklärt sie in Klartext: wer Mails im Namen deiner Domain verschickt hat, ob sie echt waren
und was die empfangenden Server damit gemacht haben – statt XML und Fehlercodes.

> *„Diese 12 Mails kamen von deinem Newsletter-Dienst und waren korrekt mit example.org
> signiert (DKIM-Selektor nl1). DMARC bestanden.“*
>
> *„Unbekannter Absender 203.0.113.5 (China, AS4134) hat versucht, als example.org zu senden
> (3 Mails): keine gültige DKIM-Signatur; SPF-Ergebnis: softfail. Der Empfänger hat sie in
> Quarantäne bzw. in den Spam-Ordner verschoben.“*

## Funktionen

- **IMAP-Abruf** über TLS; Berichte als `.xml`, `.json`, `.gz` oder `.zip`, egal mit welchem
  MIME-Typ. Verarbeitete Mails werden markiert oder verschoben, nie gelöscht. Doppelte
  Berichte werden erkannt.
- **Übersicht pro Domain:** DMARC-Bestehensquote, Verlauf pro Tag, veröffentlichte
  Richtlinie, TLS-Ergebnisse
- **Klartext-Erklärungen** für jeden Berichtseintrag und jeden TLS-Fehlertyp
- **Einordnung der Absender:** eigener Server, beauftragte Dienste (z. B. am DKIM-Selektor),
  Weiterleitungen und Unbekannte, mit Reverse-DNS und optional GeoIP/ASN
- **Push-Meldungen** über Pushover bei neuen Fehlschlägen und unbekannten Absendern, entprellt
- **Anmeldung über den Reverse-Proxy** (Forward-Auth-Header wie `Remote-User`), keine eigenen Passwörter
- **Geheimnisse aus Dateien** (`IMAP_PASSWORD_FILE`, `PUSHOVER_TOKEN_FILE`, …) für Docker-Secrets
- **Hochladen** alter Berichtsdateien, **Hilfeseiten** zu SPF, DKIM, DMARC, Ausrichtung und TLS-RPT
- Deutsch und Englisch, heller und dunkler Modus, auch fürs Handy
- Kleiner Container: SQLite, ohne Root-Rechte, schreibgeschütztes Dateisystem, eingebauter Healthcheck

## Schnellstart

```bash
mkdir mailreports && cd mailreports
curl -O https://raw.githubusercontent.com/Schnuecks/mailreports/main/compose.yaml
curl -o .env https://raw.githubusercontent.com/Schnuecks/mailreports/main/.env.example
curl -o sources.toml https://raw.githubusercontent.com/Schnuecks/mailreports/main/sources.example.toml
mkdir secrets && printf '%s' 'dein-imap-passwort' > secrets/imap_password.txt
docker compose up -d
```

Danach http://localhost:8080 öffnen. Den `rua=`-Eintrag deines DMARC-Records und den
TLS-RPT-Eintrag (`_smtp._tls`) auf das Postfach zeigen lassen; die ersten Berichte kommen
innerhalb eines Tages.

## Dokumentation

- [Installation](docs/de/installation.md) – Docker, Reverse-Proxy und Anmeldung, GeoIP
- [Einstellungen](docs/de/configuration.md) – alle Einstellungen und die Datei für bekannte Absender
- [Bedienung](docs/de/usage.md) – was die Seiten zeigen und wie Absender eingeordnet werden
- [Entwicklung](CONTRIBUTING.md)

## Unterstützen

Wenn dir mailreports hilft, kannst du mir gern einen Kaffee auf Ko-fi ausgeben:

<a href="https://ko-fi.com/schnuecks"><img src="https://ko-fi.com/img/githubbutton_sm.svg" alt="Support me on Ko-fi"></a>

## Lizenz

[GNU Affero General Public License v3.0 oder neuer](LICENSE)
