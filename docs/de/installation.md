# Installation

mailreports läuft als Docker-Container (amd64 und arm64). Es braucht ein Postfach, in dem
die Berichte ankommen, und ein Volume für die SQLite-Datenbank.

## 1. DNS: Berichte an ein Postfach schicken

DMARC-Aggregate-Berichte gehen an die Adresse im `rua=`-Eintrag deines DMARC-Records,
SMTP-TLS-Berichte an die Adresse im TLS-RPT-Record:

```
_dmarc.example.org.     TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.org"
_smtp._tls.example.org. TXT "v=TLSRPTv1; rua=mailto:dmarc@example.org"
```

Gehört das Postfach zu einer anderen Domain als der berichteten, muss diese Domain das
erlauben (RFC 7489, Abschnitt 7.1), z. B. `example.org._report._dmarc.example.net TXT "v=DMARC1"`.

## 2. Container starten

```bash
mkdir mailreports && cd mailreports
curl -O https://raw.githubusercontent.com/Schnuecks/mailreports/main/compose.yaml
curl -o .env https://raw.githubusercontent.com/Schnuecks/mailreports/main/.env.example
curl -o sources.toml https://raw.githubusercontent.com/Schnuecks/mailreports/main/sources.example.toml
mkdir secrets && printf '%s' 'dein-imap-passwort' > secrets/imap_password.txt
```

In `.env` `IMAP_HOST` und `IMAP_USER` eintragen, in `sources.toml` den eigenen Mailserver
beschreiben (siehe [Einstellungen](configuration.md)) und starten:

```bash
docker compose up -d
docker compose exec mailreports python -m mailreports check   # prüft die IMAP-Anmeldung
```

Die Seite ist unter http://localhost:8080 erreichbar. Der erste Abruf läuft direkt nach dem
Start, danach alle 15 Minuten (`FETCH_INTERVAL`).

Der Container läuft als Benutzer 10001. Bei einem eingebundenen Ordner `./data` muss dieser
für ihn beschreibbar sein: `sudo chown 10001 data`.

## 3. Hinter einem Reverse-Proxy mit Anmeldung

Mit eingebauten Konten `PUBLIC_URL` auf die Adresse im Browser setzen (z. B.
`https://dmarc.example.org`), damit Passkeys und Single Sign-on funktionieren und das
Sitzungs-Cookie nur über HTTPS gilt. Ist bereits ein Reverse-Proxy mit Anmeldung (Forward-Auth)
vorhanden, kann mailreports ihn statt der eigenen Konten nutzen und den Header prüfen, den der
Proxy setzt:

```
AUTH_HEADER=Remote-User        # Anfragen ohne diesen Header werden abgewiesen (401)
ALLOWED_GROUPS=admins          # optional, verglichen mit Remote-Groups
TRUSTED_PROXIES=172.20.0.5     # nur Anfragen vom Proxy selbst annehmen
```

Dem Header kann man nur trauen, wenn sonst niemand den Container erreicht: keinen Port
veröffentlichen und `TRUSTED_PROXIES` **so eng wie möglich setzen – auf die Adresse des
Proxys, nicht auf das ganze Docker-Netz.** Sonst könnte jeder Container im vertrauten Netz
den Anmelde-Header selbst mitschicken. Von welcher Adresse die Anfragen wirklich kommen,
steht im Container-Log (`docker compose logs mailreports` zeigt bei jeder Anfrage die
Absenderadresse): bei einem Proxy-Container ist es seine IP im gemeinsamen Netz, bei einem
Proxy mit `network_mode: host` das Gateway dieses Netzes (z. B. `172.20.0.1`). `AUTH_HEADER`
ohne `TRUSTED_PROXIES` verweigert mailreports beim Start, ein ganzes vertrautes Netz führt
zu einer Warnung im Log. `compose.traefik.yml` zeigt ein vollständiges Beispiel. Der
angezeigte Name kommt aus `Remote-Name`, falls gesetzt.

## 4. GeoIP (optional)

Mit den kostenlosen MaxMind-GeoLite2-Datenbanken zeigen die Seiten Land und Netz (AS) jeder
sendenden IP. Den Ordner mit den `.mmdb`-Dateien nach `/geoip` einbinden:

```yaml
volumes:
  - /pfad/zu/geoip:/geoip:ro
```

`GeoLite2-City.mmdb` oder `GeoLite2-Country.mmdb` liefern das Land, `GeoLite2-ASN.mmdb` den
Netzbetreiber. Die Statusseite zeigt, welche Datenbanken gefunden wurden. Aktuell halten
lassen sie sich mit MaxMinds `geoipupdate`-Container.

## Alte Berichte importieren

Anderswo gespeicherte Berichte lassen sich auf der Statusseite hochladen oder auf der
Kommandozeile importieren:

```bash
docker compose exec mailreports python -m mailreports import /data/alte-berichte/
```

Erlaubt sind `.xml`, `.json`, `.gz`, `.zip` oder ganze Mails (`.eml`). Bekannte Berichte
werden übersprungen.

## Aktualisieren

```bash
docker compose pull && docker compose up -d
```
