# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately through
GitHub instead: on the repository page open **Security → Report a vulnerability**. You will
get an answer within a few days, and a fix is released as soon as possible.

If that option is not shown, contact the maintainer [@Schnuecks](https://github.com/Schnuecks)
through GitHub and ask for a private channel, without describing the problem publicly.

Helpful details: the mailreports version (shown in the page footer), how it is deployed
(behind a reverse proxy or directly) and the steps to reproduce.

## Supported versions

Security fixes go into the latest release. Please update to it before reporting.

## Scope

mailreports reads emails from a mailbox that anyone on the internet can write to. Report
files are therefore treated as untrusted input:

- XML is parsed with `defusedxml`; entity definitions and external references are refused.
- Compressed files are unpacked with one size limit for the whole email (50 MB), at most 20
  files per zip archive and a nesting limit, so zip and gzip bombs are rejected. Emails larger
  than 25 MB are not downloaded at all.
- Every email is marked as failed before it is processed and only marked as done afterwards,
  so an email that crashes the process is not retried on every fetch.
- With `DOMAINS` set, reports for other domains are not stored.
- DMARC and TLS reports are not signed: anybody can send made-up reports to the public report
  address. Treat unexpected findings with care and set `DOMAINS`.
- All text from reports is escaped in the pages; the page uses a strict Content Security
  Policy without inline code and loads nothing from third parties.
- Emails are only read and flagged or moved, never deleted.
- The CSV export prefixes cells starting with `=`, `+`, `-` or `@` so spreadsheet programs do
  not run report data as formulas.
- The DNS check fetches the MTA-STS policy only from public addresses, never from internal
  networks.

Access:

- Every page requires a sign-in. Built-in accounts: passwords hashed with Argon2id; session
  tokens, setup and recovery codes stored only as SHA-256 hashes; HttpOnly session cookie
  (with the `__Host-` prefix over HTTPS); CSRF token on every form; failed sign-ins limited
  per username and address (behind a proxy from `TRUSTED_PROXIES`, the visitor's address
  from `X-Forwarded-For` is used); optional two-factor sign-in (TOTP, passkeys/WebAuthn) with
  authenticator keys encrypted by `SECRET_KEY`; single sign-on with PKCE, nonce and a
  state cookie bound to the browser; a sign-in log. The first account needs a setup code
  from the container log.
- Alternatively a login proxy with `AUTH_HEADER`. The header is only trusted together with
  `TRUSTED_PROXIES` (the app refuses to start without it);
  set it to the proxy's own address, not the whole Docker network, and do not publish the
  port, otherwise other containers could send the header themselves.
- `/metrics` and `/api/metrics` can be opened with `METRICS_TOKEN` without signing in; the
  token grants nothing else.
- Form posts are only accepted from the same site (`Sec-Fetch-Site`, otherwise `Origin`).
- Credentials (IMAP, Pushover) can be read from files (`*_FILE`). They are never logged or
  shown on the pages.
- The container runs as an unprivileged user and works with a read-only file system and
  without capabilities.
