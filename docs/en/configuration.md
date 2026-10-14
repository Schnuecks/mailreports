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
| `RETENTION_DAYS` | 0 | Delete reports older than this many days (checked daily); `0` keeps them forever. 400 keeps a little more than a year. |

Emails are never deleted. Emails with one of the two keywords are skipped on later fetches.
A report that is already stored (same organisation and report ID) counts as a duplicate.

## Display

| Variable | Default | Meaning |
|---|---|---|
| `APP_TITLE` | `mailreports` | Name in the header and the browser tab |
| `LOGO_URL` | built-in icon | Logo (34 px in the header) and favicon, e.g. an HTTPS URL |
| `DEFAULT_LANGUAGE` | browser language | `de`, `en`, `fr`, `es`, `it` or `nl` |
| `DOMAINS` | all | Comma-separated: which domains the overview shows, in this order |
| `TZ` | `UTC` | Time zone for dates, e.g. `Europe/Berlin` |
| `SOURCE_URL` | `https://github.com/Schnuecks/mailreports` | Link to the source code in the footer; empty hides it |

## Notifications

Findings are sent to every configured channel.

| Variable | Default | Meaning |
|---|---|---|
| `PUSHOVER_TOKEN`, `PUSHOVER_USER` | – | Pushover application token and user or group key (or `_FILE`) |
| `NTFY_URL` | – | ntfy topic address, e.g. `https://ntfy.sh/my-topic` |
| `NTFY_TOKEN` | – | Access token for a protected ntfy topic (or `_FILE`) |
| `WEBHOOK_URL` | – | Receives a JSON POST with `title`, `message`, `url` and `findings` |
| `SMTP_HOST`, `SMTP_PORT` | –, 587 (465 for ssl) | Mail server for notifications by email |
| `SMTP_SECURITY` | `starttls` | `starttls`, `ssl` or `none` |
| `SMTP_USER`, `SMTP_PASSWORD` | – | Login at the mail server (or `_FILE`) |
| `SMTP_FROM` | – | Sender address |
| `NOTIFY_EMAIL` | – | Comma-separated recipients |
| `NOTIFY_COOLDOWN_HOURS` | 24 | The same finding is reported at most once in this time |
| `DIGEST` | `off` | `weekly`: a summary of the last 7 days to all channels |
| `DIGEST_WEEKDAY` | `mon` | Day of the summary (`mon` … `sun`), sent after 8:00 local time |
| `BASE_URL` | – | Public address, added as a link to the messages |

A message is sent after a fetch when new reports contain emails that failed DMARC (except
recognised forwarding), senders that passed but are not in `sources.toml`, or TLS failures.
A finding is identified by domain and IP (or domain and TLS failure type).

## Sign-in and accounts

mailreports always requires a sign-in. There are two ways:

- **Built-in accounts** (default): user accounts with password, optional two-factor sign-in
  with an authenticator app, passkeys and security keys, single sign-on through an OpenID
  Connect provider, and a sign-in log. On first start without an account the page asks for a
  setup code from the container log and creates the first admin account.
- **Login proxy** (`AUTH_HEADER`): a reverse proxy with forward auth signs people in; the app
  trusts its header. There are no account pages in this mode.

Accounts have one of two roles: **administrator** (manage users, upload reports, start a
fetch) or **read access**.

| Variable | Default | Meaning |
|---|---|---|
| `PUBLIC_URL` | – | Address in the browser, e.g. `https://dmarc.example.org`. Needed behind a reverse proxy for passkeys and single sign-on; also makes the session cookie HTTPS-only. |
| `ADMIN_USERNAME` | `admin` | Name of the first account created from `ADMIN_PASSWORD` |
| `ADMIN_PASSWORD` | – | Creates the first admin account on start if there is none yet, instead of the setup code (better: `ADMIN_PASSWORD_FILE`). The password itself or an Argon2 hash from `python -m mailreports hash-password`. Ignored once accounts exist. |
| `SECRET_KEY` | – | Encrypts the authenticator keys in the database (any long random text, better: `SECRET_KEY_FILE`). Keep it: without it, codes of existing two-factor sign-ins stop working. |
| `COOKIE_SECURE` | automatic | `true`/`false` overrides whether the session cookie is sent over HTTPS only |
| `AUTH_DISABLED` | `false` | `true`: no sign-in at all. Only for local tests – everybody who reaches the port sees everything. |

Five failed sign-ins per username (ten per address) block for 15 minutes. A session lasts
30 days and is extended while in use; changing a password ends all sessions of that account.

### Single sign-on (OpenID Connect)

| Variable | Default | Meaning |
|---|---|---|
| `OIDC_ISSUER` | – | Address of the provider, e.g. `https://auth.example.org` (HTTPS only) |
| `OIDC_CLIENT_ID` | – | Client ID registered at the provider |
| `OIDC_CLIENT_SECRET` | – | Client secret (better: `OIDC_CLIENT_SECRET_FILE`) |
| `OIDC_NAME` | `SSO` | Label of the button: "Sign in with …" |
| `OIDC_ADMIN_GROUP` | – | Members of this group become administrators |
| `OIDC_ALLOWED_GROUP` | – | Only members of this group (or the admin group) may sign in |
| `OIDC_CREATE_USERS` | `false` | Create an account on first sign-in; otherwise only existing accounts (matched by username or verified email) can sign in |

Register `PUBLIC_URL/oidc/callback` as redirect URI at the provider, with the scopes
`openid profile email groups`.

### Login proxy

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_HEADER` | – | Header with the user name set by the login proxy, e.g. `Remote-User`. If set, requests without it get 401. Requires `TRUSTED_PROXIES`, otherwise mailreports refuses to start. |
| `ALLOWED_GROUPS` | – | Comma-separated; at least one must appear in `Remote-Groups` |
| `TRUSTED_PROXIES` | – | Comma-separated addresses or networks; requests from anywhere else get 403. Use the proxy's single address, not the whole network (see [Installation](installation.md#3-behind-a-reverse-proxy-with-login)). |

`/healthz` is always reachable for the container health check.

## Key figures

`/api/metrics` returns the figures per domain for 7 and 30 days as JSON (messages, passed,
failed, pass rate, quarantined, rejected, TLS sessions, unknown sources, policy) – suitable for
dashboard widgets. `/metrics` returns the same in the Prometheus text format.

| Variable | Default | Meaning |
|---|---|---|
| `METRICS_TOKEN` | – | With a token, both addresses can be read without signing in: `Authorization: Bearer <token>` or `?token=<token>`. Without it, only signed-in users can read them. |

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
