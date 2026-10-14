# Usage

## Overview

One card per domain for the chosen period (7, 30, 90 days or a year): the share of emails
that passed DMARC, the number of emails and reports, the published policy and the daily
history (passed below, failed on top). Below the cards, **What stood out** lists the emails
that failed DMARC, merged per domain and sending IP, in plain words.

Each card leads to the **domain page** with the published policy explained, the history,
the most frequent sending IPs, TLS results and the latest reports.

## DNS check and policy recommendation

The domain page has a button **Check DNS**. It looks up the records that are published right
now and points out problems: the DMARC record (policy, report address and its authorisation
at another domain), SPF (final `all`, the limit of 10 DNS lookups), every DKIM selector seen in
the reports with its key length, MX with DANE/TLSA, MTA-STS (mode and whether every MX is in
the policy) and TLS-RPT. Results are kept for 10 minutes.

The card **Recommendation** evaluates the last 30 days: if all known sources pass DMARC and no
unknown source passes, it suggests the next stricter policy (`p=none` → `p=quarantine` →
`p=reject`) including the record; otherwise it lists what to fix first.

## DMARC reports

The list can be filtered by domain, reporting organisation and "only with failures". A
report shows each of its records twice: first as a sentence ("These 12 emails came from …"),
then in detail with the sending IP, reverse DNS, country and network, Header From and
Envelope From, every DKIM signature with its selector, and the SPF check. The original file can
be downloaded from the report page, and the list exports all records of the filtered reports
as CSV.

Good to know when reading reports:

- An email passes DMARC if **either** DKIM or SPF passed **and** matches the sender domain.
- SPF failing alone is normal for forwarded emails; DKIM survives forwarding.
- Reports describe one day, usually from 00:00 to 23:59 UTC. Large providers send them the
  next day, so today is almost always empty.

## Senders

All sending IPs of the period with their classification:

| Classification | Meaning |
|---|---|
| Own server | matches an `own` entry in `sources.toml` |
| Authorised service | matches a `relay` entry, e.g. by its DKIM selector |
| Forwarding | a `forwarder` entry, a forwarding note in the report, or DKIM valid while SPF failed |
| Unknown | everything else |

Known sources are shown with their name from `sources.toml`; hover over it to see the type.

Every IP address links to its own page with history, classification, reverse DNS, country and
network and all its records. The search field at the top finds IP addresses, host names,
domains, reporting organisations, report IDs and DKIM selectors.

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
stored reports, which extras are active (GeoIP, reverse DNS, known sources, notifications) and
the emails processed last, with the reason when an email did not contain a usable report.

## Settings

Admins set up the notifications here: Pushover, ntfy, webhook and email, how often the same
finding may be reported and the weekly summary. **Save and send a test message** checks the
channels at once and shows the result per channel. An empty password field keeps the stored
value; **remove** deletes it. Fields set by environment variables are shown as fixed.

## Accounts

The account page (your name at the top right) offers:

- **Two-factor sign-in** with an authenticator app: scan the QR code and confirm with a
  code. Eight recovery codes are shown once; each replaces the second factor one time.
- **Passkeys and security keys:** sign in without a password, or as second factor after a
  password. Passkeys are bound to the address in `PUBLIC_URL`.
- **Change password** (ends all other sessions) and **active sessions** with the option to
  end them.

Administrators manage accounts under **Users** (create, set a password, change the role,
disable, reset the second factors, delete) and see the **sign-in log** with successful and
refused sign-ins. The last active administrator cannot be removed.

## Command line

```bash
python -m mailreports check            # settings and IMAP login
python -m mailreports fetch            # fetch once
python -m mailreports import FILES...  # import files or folders (.xml .json .gz .zip .eml)
python -m mailreports create-user NAME [--admin]
python -m mailreports set-password NAME
python -m mailreports reset-2fa NAME   # removes authenticator app, passkeys, recovery codes
python -m mailreports list-users
python -m mailreports setup-code
```

In Docker: `docker compose exec mailreports python -m mailreports check`.
