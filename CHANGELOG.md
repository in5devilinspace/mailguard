# Changelog

## 0.1.0

First release.

- `mailguard domain <domain>` audits SPF, DMARC, DKIM and MX and prints a graded report (text or JSON).
- `mailguard headers [file | -]` explains Received hops, Authentication-Results, DKIM-Signature headers and identifier alignment without touching the network.
- BIMI, MTA-STS and TLS-RPT records are reported after the graded checks as information only.
- `--zone file.json` runs the domain audit against an offline zone file so a DNS change can be checked before it is published.
- Zero runtime dependencies; TypeScript executed directly by Node 24 or newer.
- A resolver that answers no query at all aborts the domain audit with exit 2 instead of grading an unchecked domain A, and an invalid `--dns` value is a usage error instead of a crash (found in review before release).
