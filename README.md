<p align="center"><img src="docs/logo.svg" width="96" alt="mailreports"></p>

# mailreports

**English** · [Deutsch](README.de.md)

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.15-3776AB?logo=python&logoColor=white" alt="Python 3.15">
  <a href="https://github.com/Schnuecks/mailreports/pkgs/container/mailreports"><img src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white" alt="Docker ready"></a>
  <img src="https://img.shields.io/badge/platform-amd64%20%7C%20arm64-E4572E" alt="Platform amd64 | arm64">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-4C9A2A" alt="License AGPL-3.0"></a>
</p>

Collects **DMARC aggregate reports** and **SMTP TLS reports** from an IMAP mailbox and
explains them in plain words: who sent mail as your domain, whether it was genuine, and what
the receiving servers did with it – instead of a wall of XML and result codes.

> *"These 12 mails came from your newsletter service: correctly signed with example.org
> (DKIM selector nl1). DMARC passed."*
>
> *"Unknown sender 203.0.113.5 (China, AS4134) tried to send as example.org (3 mails): no
> valid DKIM signature; SPF result: softfail. The receiver quarantined them."*

## Features

- **IMAP fetch** over TLS; reports as `.xml`, `.json`, `.gz` or `.zip`, whatever the MIME type.
  Processed mails are flagged or moved, never deleted. Duplicates are recognised.
- **Overview per domain:** DMARC pass rate, daily history, published policy, TLS results
- **Plain-language explanations** for every report record and every TLS failure type
- **Sender classification:** your own server, authorised services (e.g. by DKIM selector),
  forwarders and unknown senders, with reverse DNS and optional GeoIP/ASN data
- **Push notifications** via Pushover for new failures and unknown senders, with a cooldown
- **Login via your reverse proxy** (forward auth headers such as `Remote-User`), no own passwords
- **Secrets from files** (`IMAP_PASSWORD_FILE`, `PUSHOVER_TOKEN_FILE`, …) for Docker secrets
- **Upload** of old report files, **help pages** on SPF, DKIM, DMARC, alignment and TLS-RPT
- German and English, light and dark mode, works on phones
- Small container: SQLite, non-root, read-only file system, built-in health check

## Quick start

```bash
mkdir mailreports && cd mailreports
curl -O https://raw.githubusercontent.com/Schnuecks/mailreports/main/compose.yaml
curl -o .env https://raw.githubusercontent.com/Schnuecks/mailreports/main/.env.example
curl -o sources.toml https://raw.githubusercontent.com/Schnuecks/mailreports/main/sources.example.toml
mkdir secrets && printf '%s' 'your-imap-password' > secrets/imap_password.txt
docker compose up -d
```

Then open http://localhost:8080. Point the `rua=` tag of your DMARC record and your
`_smtp._tls` TLS-RPT record at the mailbox; the first reports arrive within a day.

## Documentation

- [Installation](docs/en/installation.md) – Docker, reverse proxy and login, GeoIP
- [Configuration](docs/en/configuration.md) – all settings and the known-sources file
- [Usage](docs/en/usage.md) – what the pages show and how senders are classified
- [Development](CONTRIBUTING.md)

## Support

If mailreports is useful to you, you can buy me a coffee on Ko-fi:

<a href="https://ko-fi.com/schnuecks"><img src="https://ko-fi.com/img/githubbutton_sm.svg" alt="Support me on Ko-fi"></a>

## License

[GNU Affero General Public License v3.0 or later](LICENSE)
