# Bedienung

## Übersicht

Eine Karte pro Domain für den gewählten Zeitraum (7, 30, 90 Tage oder ein Jahr): der Anteil
der Mails, die DMARC bestanden haben, die Zahl der Mails und Berichte, die veröffentlichte
Richtlinie und der Verlauf pro Tag (unten bestanden, oben durchgefallen). Unter den Karten
listet **Was auffiel** die Mails, die DMARC verfehlt haben, zusammengefasst pro Domain und
sendender IP, in Klartext.

Jede Karte führt zur **Domain-Seite** mit erklärter Richtlinie, Verlauf, den häufigsten
sendenden IPs, TLS-Ergebnissen und den neuesten Berichten.

## DNS-Prüfung und Empfehlung zur Richtlinie

Die Domain-Seite hat die Schaltfläche **DNS prüfen**. Sie fragt die aktuell veröffentlichten
Einträge ab und weist auf Probleme hin: DMARC-Eintrag (Richtlinie, Berichtsadresse und deren
Freigabe bei einer fremden Domain), SPF (abschließendes `all`, Grenze von 10 DNS-Abfragen), jeder
in den Berichten gesehene DKIM-Selektor mit Schlüssellänge, MX mit DANE/TLSA, MTA-STS (Modus und
ob jeder MX in der Richtlinie steht) und TLS-RPT. Ergebnisse werden 10 Minuten zwischengespeichert.

Die Karte **Empfehlung** wertet die letzten 30 Tage aus: Bestehen alle bekannten Quellen DMARC und
besteht keine unbekannte Quelle, schlägt sie die nächststrengere Richtlinie vor (`p=none` →
`p=quarantine` → `p=reject`), samt Eintrag; sonst nennt sie, was vorher zu klären ist.

## DMARC-Berichte

Die Liste lässt sich nach Domain, berichtender Organisation und „nur mit Fehlschlägen“
filtern. Ein Bericht zeigt jeden Eintrag zweimal: zuerst als Satz („Diese 12 Mails kamen
von …“), dann im Detail mit sendender IP, Reverse-DNS, Land und Netz, Header-From und
Envelope-From, jeder DKIM-Signatur mit Selektor und der SPF-Prüfung. Die Originaldatei lässt
sich auf der Berichtsseite herunterladen, und die Liste exportiert alle Einträge der gefilterten
Berichte als CSV.

Gut zu wissen beim Lesen:

- Eine Mail besteht DMARC, wenn DKIM **oder** SPF bestanden hat **und** zur
  Absender-Domain passt.
- Nur SPF durchgefallen ist bei weitergeleiteten Mails normal; DKIM übersteht die
  Weiterleitung.
- Berichte beschreiben einen Tag, meist von 0:00 bis 23:59 Uhr UTC. Große Anbieter schicken
  sie am Folgetag, deshalb ist „heute“ fast immer leer.

## Absender

Alle sendenden IPs des Zeitraums mit ihrer Einordnung:

| Einordnung | Bedeutung |
|---|---|
| Eigener Server | passt zu einem `own`-Eintrag in `sources.toml` |
| Beauftragter Dienst | passt zu einem `relay`-Eintrag, z. B. über den DKIM-Selektor |
| Weiterleitung | ein `forwarder`-Eintrag, ein Weiterleitungs-Hinweis im Bericht oder gültiges DKIM bei fehlgeschlagenem SPF |
| Unbekannt | alles andere |

Bekannte Quellen erscheinen mit ihrem Namen aus `sources.toml`; mit der Maus darüber zeigt sich die Art.

Jede IP-Adresse führt zu einer eigenen Seite mit Verlauf, Einordnung, Reverse-DNS, Land und Netz
und allen ihren Einträgen. Das Suchfeld oben findet IP-Adressen, Hostnamen, Domains, berichtende
Organisationen, Bericht-IDs und DKIM-Selektoren.

Ein **unbekannter Absender, der DMARC besteht**, ist meist ein Dienst, den du noch nicht
eingetragen hast. Ein **unbekannter Absender, der durchfällt**, ist meist jemand, der deine
Domain missbrauchen will – genau das hat DMARC verhindert. Der Abschnitt **Bekannte
Quellen** unten zeigt, was die App aus `sources.toml` gelesen hat.

## TLS-Berichte

Pro Domain und Richtlinie (MTA-STS, DANE oder keine) die Zahl der erfolgreichen und
fehlgeschlagenen Verbindungen und bei Fehlern, was schiefging und was zu tun ist (etwa ein
abgelaufenes Zertifikat oder ein TLSA-Eintrag, der nach einem Zertifikatswechsel nicht mehr
passt).

## Status

Postfach und letzter Abruf (mit Knopf **Jetzt abrufen**), Hochladen von Berichtsdateien, die
Zahl der gespeicherten Berichte, welche Zusatzdienste aktiv sind (GeoIP, Reverse-DNS,
bekannte Quellen, Benachrichtigungen) und die zuletzt verarbeiteten Mails, mit dem Grund, wenn
eine Mail keinen verwertbaren Bericht enthielt.

## Einstellungen

Admins richten hier die Benachrichtigungen ein: Pushover, ntfy, Webhook und E-Mail, wie oft
derselbe Fund gemeldet werden darf und die Wochenübersicht. **Speichern und Testnachricht
senden** prüft die Kanäle sofort und zeigt das Ergebnis je Kanal. Ein leeres Passwortfeld behält
den gespeicherten Wert, **entfernen** löscht ihn. Über Umgebungsvariablen gesetzte Felder
erscheinen als festgelegt.

## Konten

Die Kontoseite (dein Name oben rechts) bietet:

- **Zwei-Faktor-Anmeldung** mit Authenticator-App: QR-Code scannen und mit einem Code
  bestätigen. Acht Wiederherstellungscodes werden einmalig angezeigt; jeder ersetzt den
  zweiten Faktor einmal.
- **Passkeys und Sicherheitsschlüssel:** Anmeldung ohne Passwort oder als zweiter Faktor nach
  dem Passwort. Passkeys sind an die Adresse in `PUBLIC_URL` gebunden.
- **Passwort ändern** (beendet alle anderen Sitzungen) und **aktive Sitzungen** mit der
  Möglichkeit, sie zu beenden.

Administratorinnen und Administratoren verwalten Konten unter **Einstellungen → Benutzer** (anlegen, Passwort
setzen, Rolle ändern, deaktivieren, zweite Faktoren zurücksetzen, löschen) und sehen das
**Anmeldeprotokoll** mit erfolgreichen und abgelehnten Anmeldungen. Das letzte aktive
Administratorkonto lässt sich nicht entfernen.

## Kommandozeile

```bash
python -m mailreports check            # Einstellungen und IMAP-Anmeldung
python -m mailreports fetch            # einmal abrufen
python -m mailreports import DATEIEN...  # Dateien oder Ordner importieren (.xml .json .gz .zip .eml)
python -m mailreports create-user NAME [--admin]
python -m mailreports set-password NAME
python -m mailreports reset-2fa NAME   # entfernt Authenticator-App, Passkeys, Wiederherstellungscodes
python -m mailreports list-users
python -m mailreports setup-code
```

Im Docker-Container: `docker compose exec mailreports python -m mailreports check`.
