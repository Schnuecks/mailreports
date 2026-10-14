# Einstellungen

Alle Einstellungen sind Umgebungsvariablen. **Jede Variable lässt sich auch aus einer Datei
lesen:** `NAME_FILE=/pfad` hat Vorrang vor `NAME` – gedacht für Docker-Secrets wie
`IMAP_PASSWORD_FILE=/run/secrets/imap_password`.

## Postfach

| Variable | Standard | Bedeutung |
|---|---|---|
| `IMAP_HOST` | – | IMAP-Server. Ohne ihn wird nichts abgerufen (Hochladen geht trotzdem). |
| `IMAP_USER` | – | Anmeldename |
| `IMAP_PASSWORD` | – | Passwort (besser: `IMAP_PASSWORD_FILE`) |
| `IMAP_PORT` | 993 (143 bei starttls) | Port |
| `IMAP_SECURITY` | `ssl` | `ssl` (direktes TLS) oder `starttls`. Zertifikate werden immer geprüft. |
| `IMAP_FOLDER` | `INBOX` | Ordner mit den Berichtsmails |
| `IMAP_MOVE_TO` | – | Ordner für verarbeitete Mails (wird angelegt). Leer: Mails bleiben liegen und werden als gelesen mit dem Schlagwort `$MailreportsDone` markiert. |
| `IMAP_ERROR_FOLDER` | – | Ordner für Mails ohne verwertbaren Bericht. Leer: Schlagwort `$MailreportsError`. |
| `IMAP_READONLY` | `false` | `true`: Postfach nur lesend öffnen und nichts verändern (keine Markierungen, kein Verschieben); verarbeitete Mails merkt sich die Datenbank. Für den Betrieb neben einem anderen Programm, das dasselbe Postfach liest. |
| `FETCH_INTERVAL` | 900 | Sekunden zwischen zwei Abrufen (mindestens 60) |

Mails werden nie gelöscht. Mails mit einem der beiden Schlagwörter werden bei späteren
Abrufen übersprungen. Ein schon gespeicherter Bericht (gleiche Organisation und Bericht-ID)
zählt als doppelt.

## Anzeige

| Variable | Standard | Bedeutung |
|---|---|---|
| `APP_TITLE` | `mailreports` | Name in der Kopfleiste und im Browser-Tab |
| `LOGO_URL` | eingebautes Symbol | Logo (34 px in der Kopfleiste) und Favicon, z. B. eine HTTPS-Adresse |
| `DEFAULT_LANGUAGE` | Browsersprache | `de` oder `en` |
| `DOMAINS` | alle | Kommagetrennt: welche Domains die Übersicht zeigt, in dieser Reihenfolge |
| `TZ` | `UTC` | Zeitzone für Datumsangaben, z. B. `Europe/Berlin` |
| `SOURCE_URL` | `https://github.com/Schnuecks/mailreports` | Link zum Quellcode in der Fußzeile; leer blendet ihn aus |

## Benachrichtigungen

| Variable | Standard | Bedeutung |
|---|---|---|
| `PUSHOVER_TOKEN` | – | Pushover-Anwendungs-Token (oder `_FILE`) |
| `PUSHOVER_USER` | – | Pushover-Benutzer- oder Gruppenschlüssel (oder `_FILE`) |
| `NOTIFY_COOLDOWN_HOURS` | 24 | Derselbe Fund wird höchstens einmal in dieser Zeit gemeldet |
| `BASE_URL` | – | Öffentliche Adresse, wird als Link an die Meldung gehängt |

Nach einem Abruf geht eine Meldung raus, wenn neue Berichte Mails enthalten, die DMARC
verfehlt haben (außer erkannten Weiterleitungen), Absender, die bestanden haben, aber nicht
in `sources.toml` stehen, oder TLS-Fehler. Ein Fund ist durch Domain und IP bestimmt (bzw.
Domain und TLS-Fehlertyp).

## Anmeldung und Konten

mailreports verlangt immer eine Anmeldung. Dafür gibt es zwei Wege:

- **Eingebaute Konten** (Standard): Benutzerkonten mit Passwort, optional Zwei-Faktor-Anmeldung
  mit Authenticator-App, Passkeys und Sicherheitsschlüssel, Single Sign-on über einen
  OpenID-Connect-Anbieter und ein Anmeldeprotokoll. Beim ersten Start ohne Konto fragt die
  Seite nach einem Einrichtungscode aus dem Container-Log und legt das erste
  Administratorkonto an.
- **Anmelde-Proxy** (`AUTH_HEADER`): Ein Reverse-Proxy mit Forward-Auth meldet an; die App
  vertraut seinem Header. Kontoseiten gibt es in diesem Modus nicht.

Konten haben eine von zwei Rollen: **Administration** (Benutzer verwalten, Berichte hochladen,
Abruf starten) oder **Lesezugriff**.

| Variable | Standard | Bedeutung |
|---|---|---|
| `PUBLIC_URL` | – | Adresse im Browser, z. B. `https://dmarc.example.org`. Hinter einem Reverse-Proxy nötig für Passkeys und Single Sign-on; das Sitzungs-Cookie gilt dann nur über HTTPS. |
| `ADMIN_USERNAME` | `admin` | Name des ersten Kontos, das aus `ADMIN_PASSWORD` angelegt wird |
| `ADMIN_PASSWORD` | – | Legt beim Start das erste Administratorkonto an, falls es noch keines gibt, statt des Einrichtungscodes (besser: `ADMIN_PASSWORD_FILE`). Das Passwort selbst oder ein Argon2-Hash aus `python -m mailreports hash-password`. Wird ignoriert, sobald Konten existieren. |
| `SECRET_KEY` | – | Verschlüsselt die Schlüssel der Authenticator-Apps in der Datenbank (beliebiger langer Zufallstext, besser: `SECRET_KEY_FILE`). Aufbewahren: Ohne ihn funktionieren die Codes bestehender Zwei-Faktor-Anmeldungen nicht mehr. |
| `COOKIE_SECURE` | automatisch | `true`/`false` legt fest, ob das Sitzungs-Cookie nur über HTTPS gesendet wird |
| `AUTH_DISABLED` | `false` | `true`: gar keine Anmeldung. Nur für lokale Tests – jeder, der den Port erreicht, sieht alles. |

Fünf fehlgeschlagene Anmeldungen pro Benutzername (zehn pro Adresse) sperren für 15 Minuten.
Eine Sitzung gilt 30 Tage und verlängert sich bei Nutzung; eine Passwortänderung beendet alle
Sitzungen des Kontos.

### Single Sign-on (OpenID Connect)

| Variable | Standard | Bedeutung |
|---|---|---|
| `OIDC_ISSUER` | – | Adresse des Anbieters, z. B. `https://auth.example.org` (nur HTTPS) |
| `OIDC_CLIENT_ID` | – | Beim Anbieter registrierte Client-ID |
| `OIDC_CLIENT_SECRET` | – | Client-Secret (besser: `OIDC_CLIENT_SECRET_FILE`) |
| `OIDC_NAME` | `SSO` | Beschriftung der Schaltfläche „Mit … anmelden“ |
| `OIDC_ADMIN_GROUP` | – | Mitglieder dieser Gruppe erhalten Administrationsrechte |
| `OIDC_ALLOWED_GROUP` | – | Nur Mitglieder dieser Gruppe (oder der Admin-Gruppe) dürfen sich anmelden |
| `OIDC_CREATE_USERS` | `false` | Beim ersten Anmelden ein Konto anlegen; sonst können sich nur bestehende Konten anmelden (zugeordnet über Benutzername oder bestätigte E-Mail-Adresse) |

Beim Anbieter `PUBLIC_URL/oidc/callback` als Redirect-URI eintragen, mit den Scopes
`openid profile email groups`.

### Anmelde-Proxy

| Variable | Standard | Bedeutung |
|---|---|---|
| `AUTH_HEADER` | – | Header mit dem Benutzernamen vom Anmelde-Proxy, z. B. `Remote-User`. Wenn gesetzt, bekommen Anfragen ohne ihn 401. Braucht `TRUSTED_PROXIES`, sonst startet mailreports nicht. |
| `ALLOWED_GROUPS` | – | Kommagetrennt; mindestens eine muss in `Remote-Groups` stehen |
| `TRUSTED_PROXIES` | – | Kommagetrennte Adressen oder Netze; Anfragen von anderswo bekommen 403. Am besten nur die Adresse des Proxys, nicht das ganze Netz (siehe [Installation](installation.md#3-hinter-einem-reverse-proxy-mit-anmeldung)). |

`/healthz` ist für den Container-Healthcheck immer erreichbar.

## Nachschlagen und Speicher

| Variable | Standard | Bedeutung |
|---|---|---|
| `DNS_LOOKUPS` | `true` | Reverse-DNS (PTR) für sendende IPs, vorwärts gegengeprüft (✓ = bestätigt) |
| `GEOIP_DIR` | `/geoip` | Ordner, in dem `GeoLite2-City.mmdb`, `GeoLite2-Country.mmdb`, `GeoLite2-ASN.mmdb` gesucht werden |
| `GEOIP_CITY_DB`, `GEOIP_COUNTRY_DB`, `GEOIP_ASN_DB` | – | Stattdessen Pfade zu einzelnen Dateien |
| `SOURCES_FILE` | `/config/sources.toml` | Bekannte Absender, siehe unten |
| `DATA_DIR` | `/data` | Datenbank `mailreports.sqlite3` |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` |

IP-Daten werden zwischengespeichert und nach 30 Tagen erneuert.

## Bekannte Absender (sources.toml)

Ohne diese Datei ist jeder Absender „unbekannt“. Trage deinen eigenen Server und jeden
Dienst ein, der in deinem Namen Mails verschickt:

```toml
[[source]]
name = "Eigener Mailserver"
kind = "own"
ips = ["192.0.2.10", "2001:db8::/64"]
ptr = ["mail.example.org"]

[[source]]
name = "Newsletter-Dienst"
kind = "relay"
dkim_selectors = ["nl1", "nl2"]
dkim_domains = ["example.org"]
note = "nur Newsletter"

[[source]]
name = "Mailinglisten-Server"
kind = "forwarder"
ptr = [".lists.example.net"]
asn = [64500]
```

| Schlüssel | Bedeutung |
|---|---|
| `name` | Erscheint auf den Seiten und in den Erklärungen |
| `kind` | `own` (eigener Server), `relay` (sendet in deinem Auftrag) oder `forwarder` (Weiterleitung) |
| `ips` | Adressen oder Netze (IPv4 und IPv6) |
| `ptr` | Reverse-DNS-Name; mit führendem Punkt alle Namen, die so enden |
| `asn` | AS-Nummern (braucht `GeoLite2-ASN.mmdb`) |
| `dkim_selectors` | Passt auf Einträge mit einer *gültigen* DKIM-Signatur mit einem dieser Selektoren |
| `dkim_domains` | Schränkt `dkim_selectors` optional auf diese Signatur-Domains ein |
| `note` | Freitext neben dem Namen |

Zuerst werden IP-, PTR- und AS-Regeln geprüft, dann DKIM-Selektoren. Einträge, auf die nichts
passt, die aber noch eine gültige DKIM-Signatur haben, während SPF fehlschlug, gelten als
wahrscheinliche Weiterleitung.
