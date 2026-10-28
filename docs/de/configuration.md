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
| `RETENTION_DAYS` | 0 | Berichte löschen, die älter als so viele Tage sind (täglich geprüft); `0` behält sie dauerhaft. 400 behält gut ein Jahr. |

Mails werden nie gelöscht. Mails mit einem der beiden Schlagwörter werden bei späteren
Abrufen übersprungen. Ein schon gespeicherter Bericht (gleiche Organisation und Bericht-ID)
zählt als doppelt.

## Anzeige

| Variable | Standard | Bedeutung |
|---|---|---|
| `APP_TITLE` | `mailreports` | Name in der Kopfleiste und im Browser-Tab |
| `THEME` | neutral | Farbschema: `neutral` (Grau und Blau) oder `olive` (Olivgrün); hell und dunkel richten sich nach dem Gerät |
| `LOGO_URL` | eingebautes Symbol | Logo (34 px in der Kopfleiste) und Favicon, z. B. eine HTTPS-Adresse |
| `DEFAULT_LANGUAGE` | Browsersprache | `de`, `en`, `fr`, `es`, `it` oder `nl` |
| `DOMAINS` | alle | Kommagetrennt: die eigenen Domains, in der Reihenfolge der Übersicht. Berichte für andere Domains werden nicht gespeichert (Subdomains der eigenen schon) – empfohlen, weil jeder Berichte an die öffentliche Berichtsadresse schicken kann |
| `TZ` | `UTC` | Zeitzone für Datumsangaben, z. B. `Europe/Berlin` |
| `SOURCE_URL` | `https://github.com/Schnuecks/mailreports` | Link zum Quellcode in der Fußzeile; leer blendet ihn aus |

## Benachrichtigungen

Funde gehen an alle eingerichteten Kanäle. Admins können die Kanäle, die Wochenübersicht und
den Mindestabstand auch in der App unter **Einstellungen** einrichten und dort eine
Testnachricht senden. Gesetzte Umgebungsvariablen haben Vorrang und erscheinen auf der Seite als
festgelegt. In der App eingegebene Tokens und Passwörter werden mit `SECRET_KEY` verschlüsselt
gespeichert (ohne ihn unverschlüsselt).

| Variable | Standard | Bedeutung |
|---|---|---|
| `PUSHOVER_TOKEN`, `PUSHOVER_USER` | – | Pushover-Anwendungs-Token und Benutzer- oder Gruppenschlüssel (oder `_FILE`) |
| `NTFY_URL` | – | Adresse des ntfy-Themas, z. B. `https://ntfy.sh/mein-thema` |
| `NTFY_TOKEN` | – | Zugriffstoken für ein geschütztes ntfy-Thema (oder `_FILE`) |
| `WEBHOOK_URL` | – | Erhält einen JSON-POST mit `title`, `message`, `url` und `findings` |
| `SMTP_HOST`, `SMTP_PORT` | –, 587 (465 bei ssl) | Mailserver für Benachrichtigungen per E-Mail |
| `SMTP_SECURITY` | `starttls` | `starttls`, `ssl` oder `none` |
| `SMTP_USER`, `SMTP_PASSWORD` | – | Anmeldung am Mailserver (oder `_FILE`) |
| `SMTP_FROM` | – | Absenderadresse |
| `NOTIFY_EMAIL` | – | Empfänger, kommagetrennt |
| `NOTIFY_COOLDOWN_HOURS` | 24 | Derselbe Fund wird höchstens einmal in dieser Zeit gemeldet |
| `DIGEST` | `off` | `weekly`: Zusammenfassung der letzten 7 Tage an alle Kanäle |
| `DIGEST_WEEKDAY` | `mon` | Tag der Zusammenfassung (`mon` … `sun`), versendet ab 8 Uhr Ortszeit |
| `DNS_WATCH` | `on` | `off`: keine tägliche DNS-Prüfung der Domains (geänderte Einträge und neue Probleme) |
| `BASE_URL` | `PUBLIC_URL` | Öffentliche Adresse, wird als Link an die Nachrichten gehängt; nur nötig, wenn sie von `PUBLIC_URL` abweicht |

Nach einem Abruf geht eine Meldung raus, wenn neue Berichte Mails enthalten, die DMARC
verfehlt haben (außer erkannten Weiterleitungen), Absender, die bestanden haben, aber nicht
in `sources.toml` stehen, oder TLS-Fehler. Ein Fund ist durch Domain und IP bestimmt (bzw.
Domain und TLS-Fehlertyp). Die tägliche DNS-Prüfung schickt eine eigene Meldung, wenn sich ein
Eintrag geändert hat oder ein neues Problem auftritt; der Webhook erhält dann `dns_changes` statt
`findings`.

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
| `PUBLIC_URL` | – | Adresse im Browser, z. B. `https://dmarc.example.org`. Hinter einem Reverse-Proxy nötig für Passkeys und Single Sign-on; das Sitzungs-Cookie gilt dann nur über HTTPS, und die Adresse dient als Link in Benachrichtigungen. Status- und Kontoseite warnen, wenn sie fehlt oder nicht zur aufgerufenen Adresse passt – bei einem Adresswechsel daran denken (und an die Rücksprung-Adresse beim Anbieter). |
| `ADMIN_USERNAME` | `admin` | Name des ersten Kontos, das aus `ADMIN_PASSWORD` angelegt wird |
| `ADMIN_PASSWORD` | – | Legt beim Start das erste Administratorkonto an, falls es noch keines gibt, statt des Einrichtungscodes (besser: `ADMIN_PASSWORD_FILE`). Das Passwort selbst oder ein Argon2-Hash aus `python -m mailreports hash-password`. Wird ignoriert, sobald Konten existieren. |
| `SECRET_KEY` | – | Verschlüsselt die Schlüssel der Authenticator-Apps und die Zugangsdaten der Benachrichtigungen aus den Einstellungen in der Datenbank (beliebiger langer Zufallstext, besser: `SECRET_KEY_FILE`). Aufbewahren: Ohne ihn funktionieren die Codes bestehender Zwei-Faktor-Anmeldungen nicht mehr, und in der App gespeicherte Zugangsdaten müssen neu eingegeben werden. |
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
| `OIDC_CREATE_USERS` | `false` | Beim ersten Anmelden ein Konto anlegen; sonst können sich nur bestehende Konten anmelden |
| `OIDC_LINK_USERNAME` | `false` | Bestehende Konten auch über den Benutzernamen zuordnen. Nur bei Anbietern, bei denen man seinen Namen nicht selbst wählen kann |

Beim ersten Anmelden wird ein bestehendes Konto über die bestätigte E-Mail-Adresse zugeordnet (mit
`OIDC_LINK_USERNAME` auch über den Benutzernamen). Administratorkonten werden nie automatisch
zugeordnet: Admins melden sich einmal mit dem Passwort an und verknüpfen das Konto beim Anbieter
unter **Konto → Single Sign-on**.

Beim Anbieter `PUBLIC_URL/oidc/callback` als Redirect-URI eintragen, mit den Scopes
`openid profile email groups`.

### Anmelde-Proxy

| Variable | Standard | Bedeutung |
|---|---|---|
| `AUTH_PORTAL_URL` | – | Anmeldeseite eines Reverse-Proxys vor mailreports, z. B. `https://auth.example.org` (mehrere durch Kommas getrennt). Formulare dürfen nur zu diesem Server, zu diesen Adressen und zu `OIDC_ISSUER` führen; ohne die Adresse passiert bei einem Formular wie „Abmelden“ nichts, sobald die Sitzung beim Proxy abgelaufen ist |
| `AUTH_HEADER` | – | Header mit dem Benutzernamen vom Anmelde-Proxy, z. B. `Remote-User`. Wenn gesetzt, bekommen Anfragen ohne ihn 401. Braucht `TRUSTED_PROXIES`, sonst startet mailreports nicht. |
| `ALLOWED_GROUPS` | – | Kommagetrennt; mindestens eine muss in `Remote-Groups` stehen |
| `TRUSTED_PROXIES` | – | Kommagetrennte Adressen oder Netze; Anfragen von anderswo bekommen 403. Am besten nur die Adresse des Proxys, nicht das ganze Netz (siehe [Installation](installation.md#3-hinter-einem-reverse-proxy-mit-anmeldung)). |

`/healthz` ist für den Container-Healthcheck immer erreichbar.

## Kennzahlen

`/api/metrics` liefert die Kennzahlen je Domain für 7 und 30 Tage als JSON (E-Mails, bestanden,
nicht bestanden, Bestehensquote, Quarantäne, abgewiesen, TLS-Verbindungen, unbekannte Quellen,
Richtlinie) – geeignet für Dashboard-Widgets. `/metrics` liefert dasselbe im Prometheus-Textformat.

| Variable | Standard | Bedeutung |
|---|---|---|
| `METRICS_TOKEN` | – | Mit Token lassen sich beide Adressen ohne Anmeldung abrufen: `Authorization: Bearer <token>` oder `?token=<token>`. Ohne Token nur für angemeldete Benutzer. |

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

Ohne bekannte Absender ist jeder Absender „unbekannt“. Admins können sie in der App eintragen
(siehe [Bedienung](usage.md#bekannten-absender-in-der-app-eintragen)) oder in dieser Datei
beschreiben – deinen eigenen Server und jeden Dienst, der in deinem Namen Mails verschickt:

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

Einträge aus der App kommen nach denen aus der Datei. Zuerst werden IP-, PTR- und AS-Regeln
geprüft, dann DKIM-Selektoren. Einträge, auf die nichts
passt, die aber noch eine gültige DKIM-Signatur haben, während SPF fehlschlug, gelten als
wahrscheinliche Weiterleitung.
