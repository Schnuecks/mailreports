# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## 1.0.1

Fixes from the first CodeQL scan after the public release:

- **Security:** the address to return to after signing in (and after switching the language)
  could lead to another site when it contained a tab, a line break or a backslash
  (`/	/example.com`); such addresses are now refused
- The health check no longer shows the text of a database error
- Smaller clean-ups: language cookie only from the fixed list, file name of `sources.toml` on
  the status page determined on the server

## 1.0.0

First public release. mailreports fetches DMARC aggregate reports and SMTP TLS reports from an
IMAP mailbox and explains them in plain words.

- **Reports:** DMARC (XML, gzip, zip) and TLS-RPT (JSON), duplicates recognised, original files
  kept for download; emails are flagged or moved, never deleted; read-only mode for a mailbox
  shared with another program
- **Plain-language explanations** for every record, sender classification (own servers and
  services from `sources.toml`, DKIM selectors, forwarders, unknown senders) with reverse DNS,
  country and network
- **Overview per domain** with pass rate and history, sender pages, search, CSV export,
  a **DNS check** (DMARC, SPF, DKIM, MX/DANE, MTA-STS, TLS-RPT) and a **policy recommendation**
- **Notifications** via Pushover, ntfy, webhook or email, set up in the app or with environment
  variables, plus an optional weekly summary; key figures as JSON and for Prometheus
- **Sign-in:** built-in accounts with roles, two-factor sign-in (authenticator app, passkeys),
  single sign-on (OpenID Connect) or a login proxy (`AUTH_HEADER` with `TRUSTED_PROXIES`)
- **Hardened:** untrusted reports parsed safely with one unpack limit per email, strict Content
  Security Policy and cross-origin headers, CSRF protection, sign-in limits, read-only
  container without root, checked with a ZAP baseline scan
- Six languages, light and dark theme in a neutral or olive green design, works on phones;
  images for amd64 and arm64

The detailed history of the test phase follows below.

## 0.4.7

- Status page tidied up: mailbox next to extras, data next to upload, in two even columns
  instead of three uneven ones
- On phones, labels and values of detail lists stand side by side instead of one below the other
- "no attachment" in the mail log is translated

## 0.4.6

- **`AUTH_PORTAL_URL`:** forms may only lead to this server, to the sign-in page of a reverse
  proxy given here and to the single sign-on provider (`OIDC_ISSUER`), instead of any HTTPS
  address (Content Security Policy `form-action`). Warning at startup when `AUTH_HEADER` is set
  without it.

## 0.4.5

Hardening from the ZAP baseline scan (no vulnerability found):

- Content Security Policy: `base-uri 'none'` and `object-src 'none'`; images from other
  servers only from the origin of an external `LOGO_URL` instead of any HTTPS address
- New headers: `Permissions-Policy`, `Cross-Origin-Opener-Policy`,
  `Cross-Origin-Resource-Policy` and `Cross-Origin-Embedder-Policy: credentialless`
- ZAP rules: false alarms and intended behaviour documented in `.zap/rules.tsv`

## 0.4.4

Security fixes from a review before the public release:

- **Memory bomb by email:** the unpack limit (50 MB) now applies to the whole email instead of
  each archive level; at most 20 files per zip archive; emails over 25 MB are not downloaded
- Every email is marked as failed before processing and as done afterwards, so an email that
  crashes the process is not retried on every fetch
- **Single sign-on:** existing accounts are no longer matched by username (only with the new
  `OIDC_LINK_USERNAME`), and administrator accounts are never matched automatically – admins
  link their provider account on the account page
- **Behind a reverse proxy** from `TRUSTED_PROXIES`, sign-in limits, the sign-in log and the
  session list use the visitor's address from `X-Forwarded-For` instead of the proxy's
- With `DOMAINS` set, reports for other domains are no longer stored
- Warning at startup when `IMAP_SECURITY=none` sends the password to a remote server
- Base image pinned by digest and GitHub Actions by commit

## 0.4.3

- Phone layout of the settings: tabs in one line with short labels, short fields side by side
- The file selection for uploads no longer sticks out of its card on phones

## 0.4.2

- **Users** and the **sign-in log** moved into **Settings** as tabs next to the notifications;
  the main menu has one entry less

## 0.4.1

- **Neutral design by default** (grey and blue, light and dark); the olive green design is still
  available with `THEME=olive`. Installations that want to keep the previous look set `THEME=olive`.
- Chart colours checked for colour vision deficiencies (blue for passed, pink for failed)
- Screenshots updated

## 0.4.0

- **Settings page** for admins: set up Pushover, ntfy, webhook and email notifications, the
  weekly summary and the cooldown in the app, and send a test message with the result per channel
- Tokens and passwords entered there are stored encrypted with `SECRET_KEY`; variables in the
  environment still take precedence and are shown as fixed
- The status page links to the settings and lists all active channels

## 0.3.1

- Notifications link to `PUBLIC_URL` when `BASE_URL` is not set (before, messages had no link)
- Warning in the log and on the status and account pages when `PUBLIC_URL` is missing or does
  not match the address in the browser, which would break passkeys and single sign-on

## 0.3.0

- **DNS check** per domain: DMARC record (policy, report address and its authorisation at
  another domain), SPF (final `all`, limit of 10 DNS lookups), DKIM selectors from the reports
  with key length, MX with DANE/TLSA, MTA-STS (mode, MX coverage) and TLS-RPT
- **Policy recommendation** on the domain page, based on the last 30 days: suggests the next
  stricter policy with the record, or lists what to fix first
- **Page per sending IP** with history, classification and all records; **search** across IP
  addresses, host names, domains, reporters, report IDs and DKIM selectors
- **Original reports** are stored (compressed) and can be downloaded; **CSV export** of all
  records of the filtered reports (formula characters escaped)
- **Retention:** `RETENTION_DAYS` deletes old reports daily; old mail logs, sign-in events,
  expired sessions and unused IP data are cleaned up as well
- **More notification channels:** ntfy (`NTFY_URL`), webhook (`WEBHOOK_URL`) and email
  (`SMTP_*`, `NOTIFY_EMAIL`), next to Pushover; optional **weekly summary** (`DIGEST=weekly`)
- **Key figures** at `/api/metrics` (JSON) and `/metrics` (Prometheus), optionally readable with
  `METRICS_TOKEN`
- **Six languages:** French, Spanish, Italian and Dutch added
- The background job now runs without IMAP as well (housekeeping, weekly summary)
- The help moved from the main menu to a "?" next to the search field and to the footer
- On phones the menu, search, help, account and languages fold into a menu button

## 0.2.0

- **User accounts** instead of the single password: administrator and read-only roles,
  first account through a setup code from the container log (or `ADMIN_PASSWORD` on the
  first start; an existing `ADMIN_PASSWORD` becomes the account `admin`)
- **Two-factor sign-in** with an authenticator app (TOTP) and single-use recovery codes;
  authenticator keys can be encrypted in the database with `SECRET_KEY`
- **Passkeys and security keys** (WebAuthn): sign-in without a password or as second factor
- **Single sign-on** through an OpenID Connect provider (`OIDC_ISSUER`, `OIDC_CLIENT_ID`,
  `OIDC_CLIENT_SECRET`), with admin and allowed groups and optional account creation
- Existing accounts can be linked with the single sign-on provider on the account page
  ("Link with …"), so signing in there leads to the same account; the link can be removed
  again
- Authorization codes and state values of single sign-on are masked in the access log
- Account page with password change and active sessions; user management and sign-in log
  for administrators; account commands on the command line (`create-user`, `set-password`,
  `reset-2fa`, `list-users`, `setup-code`)
- CSRF token on every form; uploading reports and starting a fetch need the administrator
  role
- More precise and neutral wording throughout the interface, in German and English
- `PUBLIC_URL` for passkeys and single sign-on behind a reverse proxy
- Running behind a login proxy (`AUTH_HEADER`) is unchanged

## 0.1.2

These changes were meant for 0.1.1 but did not make it into that release.

- **Sign-in required:** without a login proxy, the page is protected by a password
  (`ADMIN_PASSWORD` or `ADMIN_PASSWORD_FILE`, plain or as an Argon2 hash from
  `python -m mailreports hash-password`), with a signed session cookie and a limit on failed
  attempts. Without a password or `AUTH_HEADER` the app refuses to start; `AUTH_DISABLED=true`
  turns sign-in off for local tests. **When updating without a login proxy, set
  `ADMIN_PASSWORD_FILE` first.**
- `AUTH_HEADER` now requires `TRUSTED_PROXIES`; without it mailreports refuses to start,
  because anyone reaching the port could otherwise send the login header
- Form posts are also checked against the `Origin` header for browsers without
  `Sec-Fetch-Site`

## 0.1.1

- Corrected wording and translations: "Im Klartext", consistent capitalisation of column
  headings and labels, "emails" instead of "mails" in English, no doubled "DMARC passed"
- Known senders are shown with their name only (the type appears on hover), percentages
  like "0 %" instead of "0.0 %", daily reports show their day instead of a time range
- For authorised services whose SPF passes for their own sender domain, the explanation no
  longer suggests changing your SPF record
- Menu on phones wraps instead of being cut off
- Link "Source code on GitHub" in the footer, configurable with `SOURCE_URL`
- Warning in the log at start when `TRUSTED_PROXIES` contains a whole network instead of
  single addresses
- Docs and `compose.traefik.yml`: set `TRUSTED_PROXIES` to the proxy's own address (the
  gateway for a proxy with `network_mode: host`), not to the whole Docker network

## 0.1.0

First version.

- Fetches DMARC aggregate reports (RFC 7489) and SMTP TLS reports (RFC 8460) from an IMAP
  mailbox over TLS; `.xml`, `.json`, `.gz` and `.zip`, independent of the MIME type
- Processed mails are flagged or moved to a folder, never deleted; duplicate reports are
  recognised by organisation and report ID
- Read-only mode (`IMAP_READONLY`) that leaves the mailbox untouched, for running next to
  another program reading the same mailbox
- Overview per domain with DMARC pass rate, daily history and published policy
- Plain-language explanations for every report record and every TLS failure type
- Sender classification from a `sources.toml` file (IP, reverse DNS, AS number, DKIM
  selector), reverse DNS with forward check, optional GeoIP and ASN data
- Pushover notifications for new failures, unknown senders and TLS failures, with a cooldown
- Access via a login proxy header (`AUTH_HEADER`, `ALLOWED_GROUPS`) and `TRUSTED_PROXIES`
- All settings can be read from files (`*_FILE`), e.g. Docker secrets
- Upload and command line import of report files and saved mails
- Help pages on SPF, DKIM, DMARC, alignment and TLS reporting
- German and English, light and dark mode
