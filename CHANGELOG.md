# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

First version.

- Fetches DMARC aggregate reports (RFC 7489) and SMTP TLS reports (RFC 8460) from an IMAP
  mailbox over TLS; `.xml`, `.json`, `.gz` and `.zip`, independent of the MIME type
- Processed mails are flagged or moved to a folder, never deleted; duplicate reports are
  recognised by organisation and report ID
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
