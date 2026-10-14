<p align="center"><img src="mailreports/static/icon.svg" width="96" alt="mailreports"></p>

# mailreports

**English** · [Deutsch](README.de.md)

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.15-3776AB?logo=python&logoColor=white" alt="Python 3.15">
  <a href="https://github.com/Schnuecks/mailreports/pkgs/container/mailreports"><img src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white" alt="Docker ready"></a>
  <img src="https://img.shields.io/badge/platform-amd64%20%7C%20arm64-E4572E" alt="Platform amd64 | arm64">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-4C9A2A" alt="License AGPL-3.0"></a>
  <img src="https://img.shields.io/badge/status-beta-E4572E" alt="Status: beta">
  <img src="https://img.shields.io/badge/maintained-yes-4C9A2A" alt="Maintained">
</p>

mailreports is a small, self-hosted viewer for the reports that mail providers send about
your domains. It fetches **DMARC aggregate reports** and **SMTP TLS reports** from an IMAP
mailbox and explains them in plain words: who sent email in the name of your domain,
whether it was genuine, and what the receiving servers did with it – instead of a wall of
XML and result codes.

![Overview with two domains](docs/screenshots/overview-dark.png)

## Features

- **Overview** per domain with the DMARC pass rate, daily history, published policy and
  TLS results, for 7, 30 or 90 days or a year
- **Plain-language explanations** for every report record, e.g. “These 118 emails came from
  Newsletter service: correctly signed with example.org (DKIM selector nl1).”, and for every
  TLS failure type, with what to do about it
- **Sender classification:** your own server, authorised services (for example by their DKIM
  selector), forwarders and unknown senders, with reverse DNS and optional GeoIP and network
  (AS) data
- **Report details** with every DKIM signature and selector, the SPF check, Header From and
  Envelope From; the original file as download and all records as CSV export
- **DNS check** of your domains: DMARC, SPF (incl. the 10-lookup limit), DKIM key lengths,
  MTA-STS, TLS-RPT, MX and DANE
- **Policy recommendation:** when it is safe to move to `p=quarantine` or `p=reject`, and
  what to fix first
- **A page per sending IP** with history and all records, and a search across IP addresses,
  host names, domains, reporters and DKIM selectors
- **IMAP fetch** over TLS; reports as `.xml`, `.json`, `.gz` or `.zip`, whatever the MIME type.
  Emails are flagged or moved, never deleted, or left completely untouched in read-only mode.
  Duplicate reports are recognised.
- **Notifications** via Pushover, ntfy, webhook or email for new failures, unknown senders and
  TLS problems, at most once a day per finding, plus an optional **weekly summary** – set up in
  the app or with environment variables
- **Key figures** as JSON and in the Prometheus format for dashboards
- **Retention:** reports older than a set number of days are deleted automatically
- **User accounts** with administrator and read-only roles, **two-factor sign-in** with an
  authenticator app and recovery codes, **passkeys and security keys**, **single sign-on**
  through an OpenID Connect provider (e.g. Authelia) and a sign-in log – or sign-in through
  your reverse proxy with forward auth headers such as `Remote-User`
- **Secrets from files** (`IMAP_PASSWORD_FILE`, `PUSHOVER_TOKEN_FILE`, …) for Docker secrets
- **Upload and import** of older report files, **help pages** on SPF, DKIM, DMARC, alignment
  and TLS reporting
- **Six languages** (English, German, French, Spanish, Italian, Dutch), light and dark theme
  (neutral or olive green), works on phones
- **Small and easy to run:** one container, one SQLite file, runs as a non-root user with a
  read-only file system and a built-in health check

| A report in plain words | Phone |
|---|---|
| ![Report with explanations](docs/screenshots/report.png) | ![Overview on a phone in light mode](docs/screenshots/mobile-light.png) |

## Quick start

You need Docker with Docker Compose and a mailbox that receives the reports (the `rua=`
address of your DMARC record and the address of your TLS-RPT record).

```bash
mkdir mailreports && cd mailreports
curl -O https://raw.githubusercontent.com/schnuecks/mailreports/main/compose.yaml
curl -o .env https://raw.githubusercontent.com/schnuecks/mailreports/main/.env.example
curl -o sources.toml https://raw.githubusercontent.com/schnuecks/mailreports/main/sources.example.toml
mkdir data secrets && sudo chown 10001 data
printf '%s' 'your-imap-password' > secrets/imap_password.txt
docker compose up -d
```

Fill in `IMAP_HOST` and `IMAP_USER` in `.env` and describe your own mail server in
`sources.toml` first. Then open `http://<server>:8080` and create the first account; the setup code is in the log
(`docker compose logs mailreports`). The first reports arrive within a day. To update: `docker compose pull && docker compose up -d`.

For use over the internet, put it behind a reverse proxy with a login; see
[Installation](docs/en/installation.md).

## Documentation

- [Installation](docs/en/installation.md): DNS records, Docker, reverse proxy and login,
  GeoIP, importing old reports, updating
- [Configuration](docs/en/configuration.md): all settings and the file with known senders
- [Usage](docs/en/usage.md): what the pages show, how senders are classified, command line
- [Development](docs/en/development.md): running locally, tests, translations, screenshots

What changed in each version is listed in the [CHANGELOG](CHANGELOG.md).

## How it's built

mailreports is developed with the help of an AI coding assistant. I define the features and
behaviour, review the changes and test them on my own mail server. Nothing is released
without passing the automated checks: the test suite and a security scan of the container
image.

## Support

mailreports is free and stays free. If it saves you time, you can buy me a coffee; it keeps
the project going. Thank you!

<p>
  <a href="https://ko-fi.com/schnuecks"><img src="https://ko-fi.com/img/githubbutton_sm.svg" alt="Support me on Ko-fi"></a>
</p>

## Feedback

Bug reports and ideas are welcome as [GitHub issues](https://github.com/schnuecks/mailreports/issues).
If a report is read or explained wrongly, please attach the file with your own domains and
IP addresses replaced. Please report security problems privately; see
[SECURITY](SECURITY.md) and [CONTRIBUTING](CONTRIBUTING.md).

## License

Copyright (C) 2026 Schnuecks

mailreports is free software under the
[GNU Affero General Public License, version 3 or later](LICENSE) (AGPL-3.0-or-later). You
may use, modify and share it.

If you distribute a modified version or offer it to others over a network, you must make
the source code of your version available to them under the same license. The “Source
code on GitHub” link in the footer does that for this version; for your own version,
point it to your source code with `SOURCE_URL`.

The program is provided without any warranty. See the [license](LICENSE) for details.
The optional GeoIP data comes from MaxMind's GeoLite2 databases, which you download
yourself under MaxMind's license; mailreports does not include them.
