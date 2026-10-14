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

mailreports reads mails from a mailbox that anyone on the internet can write to. Report
files are therefore treated as untrusted input:

- XML is parsed with `defusedxml`; entity definitions and external references are refused.
- Compressed files are unpacked with a size limit (50 MB) and a nesting limit, so zip and
  gzip bombs are rejected.
- All text from reports is escaped in the pages; the page uses a strict Content Security
  Policy without inline code and loads nothing from third parties.
- Mails are only read and flagged or moved, never deleted.

Access:

- The app has no user accounts. Protect it with a login proxy and `AUTH_HEADER`; set
  `TRUSTED_PROXIES` to the proxy's own address (not the whole Docker network) and do not
  publish the port, otherwise clients or other containers could send the header themselves.
- Form posts are only accepted from the same site (`Sec-Fetch-Site`).
- Credentials (IMAP, Pushover) can be read from files (`*_FILE`). They are never logged or
  shown on the pages.
- The container runs as an unprivileged user and works with a read-only file system and
  without capabilities.
