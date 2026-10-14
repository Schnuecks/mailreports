# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## 0.2.0

- **User accounts** instead of the single password: administrator and read-only roles,
  first account through a setup code from the container log (or `ADMIN_PASSWORD` on the
  first start; an existing `ADMIN_PASSWORD` becomes the account `admin`)
- **Two-factor sign-in** with an authenticator app (TOTP) and single-use recovery codes;
  authenticator keys can be encrypted in the database with `SECRET_KEY`
- **Passkeys and security keys** (WebAuthn): sign-in without a password or as second factor
- **Single sign-on** through an OpenID Connect provider (`OIDC_ISSUER`, `OIDC_CLIENT_ID`,
  `OIDC_CLIENT_SECRET`), with admin and allowed groups and optional account creation
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
