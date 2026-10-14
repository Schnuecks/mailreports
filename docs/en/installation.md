# Installation

mailreports runs as a Docker container (amd64 and arm64). It needs a mailbox that receives
the reports and a volume for its SQLite database.

## 1. DNS: send the reports to a mailbox

DMARC aggregate reports go to the address in the `rua=` tag of your DMARC record, SMTP TLS
reports to the address in the TLS-RPT record:

```
_dmarc.example.org.     TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.org"
_smtp._tls.example.org. TXT "v=TLSRPTv1; rua=mailto:dmarc@example.org"
```

If the mailbox belongs to another domain than the one being reported on, that domain must
allow it (RFC 7489, section 7.1), e.g. `example.org._report._dmarc.example.net TXT "v=DMARC1"`.

## 2. Start the container

```bash
mkdir mailreports && cd mailreports
curl -O https://raw.githubusercontent.com/Schnuecks/mailreports/main/compose.yaml
curl -o .env https://raw.githubusercontent.com/Schnuecks/mailreports/main/.env.example
curl -o sources.toml https://raw.githubusercontent.com/Schnuecks/mailreports/main/sources.example.toml
mkdir secrets && printf '%s' 'your-imap-password' > secrets/imap_password.txt
```

Fill in `IMAP_HOST` and `IMAP_USER` in `.env`, describe your own mail server in
`sources.toml` (see [Configuration](configuration.md)) and start it:

```bash
docker compose up -d
docker compose exec mailreports python -m mailreports check   # tests the IMAP login
```

The page is at http://localhost:8080. The first fetch runs right after the start, then every
15 minutes (`FETCH_INTERVAL`).

The container runs as user 10001. If you bind-mount `./data`, make it writable for that
user: `sudo chown 10001 data`.

## 3. Behind a reverse proxy with login

mailreports has no user management of its own. Put it behind a reverse proxy with a login
(forward auth) and let the app check the header the proxy sets:

```
AUTH_HEADER=Remote-User        # requests without it are refused (401)
ALLOWED_GROUPS=admins          # optional, compared with Remote-Groups
TRUSTED_PROXIES=172.20.0.5     # only accept requests from the proxy itself
```

The header can only be trusted if nobody else can reach the container: do not publish the
port, and set `TRUSTED_PROXIES` **as narrow as possible – the proxy's own address, not the
whole Docker network.** Every container in a trusted network could otherwise send the login
header itself. Find the address the requests really come from in the container log
(`docker compose logs mailreports` shows the client address of every request): for a proxy
container that is its IP in the shared network, for a proxy with `network_mode: host` it is
the gateway of that network (e.g. `172.20.0.1`). `AUTH_HEADER` without `TRUSTED_PROXIES` is refused at start, and a whole trusted network
causes a warning in the log. `compose.traefik.yml` shows a complete example. The display name comes from `Remote-Name`, if set.

## 4. GeoIP (optional)

With the free MaxMind GeoLite2 databases the pages show the country and network (AS) of
every sending IP. Mount the directory with the `.mmdb` files to `/geoip`:

```yaml
volumes:
  - /path/to/geoip:/geoip:ro
```

`GeoLite2-City.mmdb` or `GeoLite2-Country.mmdb` provide the country, `GeoLite2-ASN.mmdb`
the network operator. The status page shows which databases were found. Keep them current
with MaxMind's `geoipupdate` container.

## Import old reports

Reports saved elsewhere can be uploaded on the status page, or imported on the command line:

```bash
docker compose exec mailreports python -m mailreports import /data/old-reports/
```

Files may be `.xml`, `.json`, `.gz`, `.zip` or whole emails (`.eml`). Known reports are skipped.

## Update

```bash
docker compose pull && docker compose up -d
```
