# Configuration

All settings are environment variables. **Every variable can also be read from a file:**
`NAME_FILE=/path` takes precedence over `NAME` – meant for Docker secrets such as
`IMAP_PASSWORD_FILE=/run/secrets/imap_password`.

## Mailbox

| Variable | Default | Meaning |
|---|---|---|
| `IMAP_HOST` | – | IMAP server. Without it nothing is fetched (upload still works). |
| `IMAP_USER` | – | Login name |
| `IMAP_PASSWORD` | – | Password (better: `IMAP_PASSWORD_FILE`) |
| `IMAP_PORT` | 993 (143 for starttls) | Port |
| `IMAP_SECURITY` | `ssl` | `ssl` (implicit TLS) or `starttls`. Certificates are always verified. |
| `IMAP_FOLDER` | `INBOX` | Folder with the report emails |
| `IMAP_MOVE_TO` | – | Folder for processed emails (created if missing). Empty: emails stay and are flagged as seen with the keyword `$MailreportsDone`. |
| `IMAP_ERROR_FOLDER` | – | Folder for emails without a usable report. Empty: keyword `$MailreportsError`. |
| `IMAP_READONLY` | `false` | `true`: open the mailbox read-only and change nothing (no flags, no moving); processed emails are remembered in the database. For running next to another program that reads the same mailbox. |
| `FETCH_INTERVAL` | 900 | Seconds between two fetches (minimum 60) |

Emails are never deleted. Emails with one of the two keywords are skipped on later fetches.
A report that is already stored (same organisation and report ID) counts as a duplicate.

## Display

| Variable | Default | Meaning |
|---|---|---|
| `APP_TITLE` | `mailreports` | Name in the header and the browser tab |
| `LOGO_URL` | built-in icon | Logo (34 px in the header) and favicon, e.g. an HTTPS URL |
| `DEFAULT_LANGUAGE` | browser language | `de` or `en` |
| `DOMAINS` | all | Comma-separated: which domains the overview shows, in this order |
| `TZ` | `UTC` | Time zone for dates, e.g. `Europe/Berlin` |
| `SOURCE_URL` | `https://github.com/Schnuecks/mailreports` | Link to the source code in the footer; empty hides it |

## Notifications

| Variable | Default | Meaning |
|---|---|---|
| `PUSHOVER_TOKEN` | – | Pushover application token (or `_FILE`) |
| `PUSHOVER_USER` | – | Pushover user or group key (or `_FILE`) |
| `NOTIFY_COOLDOWN_HOURS` | 24 | The same finding is reported at most once in this time |
| `BASE_URL` | – | Public address, added as a link to the message |

A message is sent after a fetch when new reports contain emails that failed DMARC (except
recognised forwarding), senders that passed but are not in `sources.toml`, or TLS failures.
A finding is identified by domain and IP (or domain and TLS failure type).

## Access

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_HEADER` | – | Header with the user name set by the login proxy, e.g. `Remote-User`. If set, requests without it get 401. Requires `TRUSTED_PROXIES`, otherwise mailreports refuses to start. |
| `ALLOWED_GROUPS` | – | Comma-separated; at least one must appear in `Remote-Groups` |
| `TRUSTED_PROXIES` | – | Comma-separated addresses or networks; requests from anywhere else get 403. Use the proxy's single address, not the whole network (see [Installation](installation.md#3-behind-a-reverse-proxy-with-login)). |

`/healthz` is always reachable for the container health check.

## Lookups and storage

| Variable | Default | Meaning |
|---|---|---|
| `DNS_LOOKUPS` | `true` | Reverse DNS (PTR) for sending IPs, checked forwards (✓ = confirmed) |
| `GEOIP_DIR` | `/geoip` | Folder searched for `GeoLite2-City.mmdb`, `GeoLite2-Country.mmdb`, `GeoLite2-ASN.mmdb` |
| `GEOIP_CITY_DB`, `GEOIP_COUNTRY_DB`, `GEOIP_ASN_DB` | – | Paths to single files instead |
| `SOURCES_FILE` | `/config/sources.toml` | Known senders, see below |
| `DATA_DIR` | `/data` | Database `mailreports.sqlite3` |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` |

IP data is cached and refreshed after 30 days.

## Known senders (sources.toml)

Without this file every sender is "unknown". Describe your own server and every service
that sends mail in your name:

```toml
[[source]]
name = "Own mail server"
kind = "own"
ips = ["192.0.2.10", "2001:db8::/64"]
ptr = ["mail.example.org"]

[[source]]
name = "Newsletter service"
kind = "relay"
dkim_selectors = ["nl1", "nl2"]
dkim_domains = ["example.org"]
note = "Newsletters only"

[[source]]
name = "Mailing list host"
kind = "forwarder"
ptr = [".lists.example.net"]
asn = [64500]
```

| Key | Meaning |
|---|---|
| `name` | Shown on the pages and in explanations |
| `kind` | `own`, `relay` (sends on your behalf) or `forwarder` |
| `ips` | Addresses or networks (IPv4 and IPv6) |
| `ptr` | Reverse DNS name; with a leading dot every name ending like this |
| `asn` | AS numbers (needs `GeoLite2-ASN.mmdb`) |
| `dkim_selectors` | Matches records with a *passing* DKIM signature using one of these selectors |
| `dkim_domains` | Optionally limits `dkim_selectors` to these signing domains |
| `note` | Free text shown next to the name |

IP, PTR and AS rules are checked first, then DKIM selectors. Records that match nothing but
still have a valid DKIM signature while SPF failed are shown as probable forwarding.
