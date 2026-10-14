# Usage

## Overview

One card per domain for the chosen period (7, 30, 90 days or a year): the share of mails
that passed DMARC, the number of mails and reports, the published policy and the daily
history (passed below, failed on top). Below the cards, **What stood out** lists the mails
that failed DMARC, merged per domain and sending IP, in plain words.

Each card leads to the **domain page** with the published policy explained, the history,
the most frequent sending IPs, TLS results and the latest reports.

## DMARC reports

The list can be filtered by domain, reporting organisation and "only with failures". A
report shows each of its records twice: first as a sentence ("These 12 mails came from …"),
then in detail with the sending IP, reverse DNS, country and network, Header From and
Envelope From, every DKIM signature with its selector, and the SPF check.

Good to know when reading reports:

- A mail passes DMARC if **either** DKIM or SPF passed **and** matches the sender domain.
- SPF failing alone is normal for forwarded mails; DKIM survives forwarding.
- Reports describe one day, usually from 00:00 to 23:59 UTC. Large providers send them the
  next day, so today is almost always empty.

## Senders

All sending IPs of the period with their classification:

| Classification | Meaning |
|---|---|
| own server | matches an `own` entry in `sources.toml` |
| authorised service | matches a `relay` entry, e.g. by its DKIM selector |
| forwarding | a `forwarder` entry, a forwarding note in the report, or DKIM valid while SPF failed |
| unknown | everything else |

An **unknown sender that passes DMARC** is usually a service you forgot to list. An
**unknown sender that fails** is usually someone abusing your domain – that is what DMARC
stopped. The section **Known sources** at the bottom shows what the app read from
`sources.toml`.

## TLS reports

Per domain and policy (MTA-STS, DANE or none) the number of successful and failed
connections, and for failures what went wrong and what to do about it (for example an
expired certificate or a TLSA record that no longer matches after a certificate change).

## Status

Mailbox and last fetch (with a **Fetch now** button), upload of report files, the number of
stored reports, which extras are active (GeoIP, reverse DNS, known sources, Pushover) and
the mails processed last, with the reason when a mail did not contain a usable report.

## Command line

```bash
python -m mailreports check            # settings and IMAP login
python -m mailreports fetch            # fetch once
python -m mailreports import FILES...  # import files or folders (.xml .json .gz .zip .eml)
```

In Docker: `docker compose exec mailreports python -m mailreports check`.
