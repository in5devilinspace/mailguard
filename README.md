# mailguard

mailguard is a command-line auditor for a domain's email authentication setup and an analyzer for the headers of a message you already received. The `domain` command looks up SPF, DMARC, DKIM and MX records, explains what it found in plain sentences and gives the domain a letter grade. The `headers` command reads an RFC 5322 header block, reconstructs the delivery path from the Received headers, reports what the receiving server decided in Authentication-Results, and checks whether the DKIM and SPF identifiers align with the From domain. It runs on Node 24 or newer with no build step and no runtime dependencies.

## Quickstart

```sh
git clone https://github.com/in5devilinspace/mailguard.git
cd mailguard
npm install
node bin/mailguard.ts domain example.com
```

`npm install` only fetches the two development dependencies that `npm test` needs (`typescript` and `@types/node`). The tool itself uses the Node standard library and nothing else, so you can also run it straight from the clone without installing anything:

```sh
node bin/mailguard.ts headers saved-message.eml
```

To see what a report looks like without touching the network, audit one of the bundled zone fixtures:

```sh
node bin/mailguard.ts domain example.com --zone test/fixtures/zones/all-good.json
```

## Commands and flags

```
mailguard domain <domain> [--json] [--zone <file.json>] [--selector <name>]... [--timeout <ms>] [--dns <ip>]...
mailguard headers [file | -] [--json]
mailguard --help
mailguard --version
```

Every command accepts `--help` (or `-h`) and prints its usage to stdout with exit code 0. A usage mistake prints the same text to stderr and exits 2.

### domain

Audits `<domain>` and prints a graded report. The domain is lowercased and a trailing dot is removed; anything that is not valid hostname syntax is a usage error.

| Flag | Meaning |
| --- | --- |
| `--json` | Print one JSON document on stdout (`JSON.stringify(report, null, 2)` plus a newline) and nothing else. Diagnostics always go to stderr. |
| `--zone <file.json>` | Answer every DNS query from an offline zone file instead of the network. Use it to dry-run a DNS change before publishing it, or to audit a domain you do not control yet. See the format below. |
| `--selector <name>` | Probe this DKIM selector in addition to the default list. Repeatable. Names are lowercased and duplicates are queried once. |
| `--timeout <ms>` | Per-query DNS timeout in milliseconds. Default 5000. Must be a positive integer. |
| `--dns <ip>` | Send queries to this resolver address instead of the system resolver. Repeatable. IPv4 or IPv6. |

`--zone` cannot be combined with `--dns` or `--timeout`; that combination is a usage error.

What the audit queries: the TXT records of the domain, of every `include:` target and of every `redirect=` target for SPF (following the chain, with cycle detection and a hard cap of 50 counted lookups); `_dmarc.<domain>` and, when that is empty and the domain has more than two labels, `_dmarc.<organizational domain>`; `<selector>._domainkey.<domain>` for each probed selector; the MX records of the domain and the A and AAAA records of each MX host; and the A and AAAA records of the domain itself when there is no MX. SPF `a`, `mx`, `ptr` and `exists` mechanisms are counted toward the RFC 7208 lookup limit but never resolved, and the extra lookups an `mx` mechanism would cause at delivery time are not counted.

Queries run concurrently (DKIM selectors five at a time) but the SPF include chain is sequential, so against a slow resolver the worst case is roughly the number of includes multiplied by the timeout.

A DNS error inside one check becomes a warning finding in that check rather than a crash. Only two things abort the audit with exit code 2: the domain does not exist at all (TXT, MX, A and AAAA all NXDOMAIN) or the resolver itself is unreachable.

### headers

Reads an RFC 5322 header block from `<file>`, or from stdin when the argument is missing or is `-`. Parsing stops at the first blank line so the body is never read; a leading Unix `From ` envelope line is skipped. CRLF and LF line endings both work. The command performs no DNS lookups and no network access; it only reports what is written in the headers.

| Flag | Meaning |
| --- | --- |
| `--json` | Print one JSON document on stdout and nothing else. |

Exit code 0 when at least one header parsed, 2 when the input is empty, unreadable or contains no headers.

### Zone file format

A zone file is a JSON object keyed by lowercase fully qualified name without a trailing dot. Each value may carry `TXT`, `MX`, `A` and `AAAA` keys. A `TXT` element is either a string (one record) or an array of strings (the character-string chunks of one record, concatenated on lookup, which is how a long DKIM key is published). `MX` is a list of `{ "priority", "exchange" }` objects; an exchange of `"."` is a null MX. Lookups are case-insensitive and ignore a trailing dot. A name that is absent from the file answers NXDOMAIN; a name that is present but lacks the requested type answers "no data", exactly like a real resolver.

```json
{
  "example.com": {
    "TXT": ["v=spf1 include:_spf.example.com -all"],
    "MX": [{ "priority": 10, "exchange": "mx1.example.com" }],
    "A": ["192.0.2.1"]
  },
  "_spf.example.com": { "TXT": ["v=spf1 ip4:192.0.2.0/24 -all"] },
  "_dmarc.example.com": { "TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"] },
  "google._domainkey.example.com": { "TXT": [["v=DKIM1; k=rsa; p=MIIBIjANBg", "...rest of the key..."]] },
  "mx1.example.com": { "A": ["192.0.2.10"], "AAAA": ["2001:db8::10"] }
}
```

A malformed zone file (not an object, a `TXT` that is not an array, an `MX` entry without a priority, unreadable path) is reported with the offending name and exit code 2.

## Example output

The `domain` command on the bundled all-good fixture:

```
$ node bin/mailguard.ts domain example.com --zone test/fixtures/zones/all-good.json
Domain: example.com
Grade: A (score 100)

SPF
  [info] SPF record for example.com is "v=spf1 include:_spf.example.com -all" and needs 1 DNS lookups

DMARC
  [info] DMARC record at _dmarc.example.com is "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s"

DKIM
  [info] DKIM selector google at google._domainkey.example.com publishes a rsa 2048-bit key

MX
  [info] MX host mx1.example.com (priority 10) resolves to 2 addresses
  [info] MX host mx2.example.com (priority 20) resolves to 1 address
```

The same command on a domain with nothing configured (exit code 1):

```
$ node bin/mailguard.ts domain example.com --zone test/fixtures/zones/nothing-configured.json
Domain: example.com
Grade: F (score 30)

SPF
  [error] example.com has no SPF record (no TXT record starting with v=spf1)

DMARC
  [error] example.com has no DMARC record at _dmarc.example.com

DKIM
  [info] No DKIM key found under the 20 probed selectors for example.com; pass --selector <name> with the selector your mail provider uses

MX
  [warning] example.com has no MX record, so mail falls back to its A/AAAA address (1 found) under the implicit MX rule
```

The `headers` command on a message that passed everything:

```
$ node bin/mailguard.ts headers test/fixtures/eml/gmail-pass.eml
From: Alice Example <alice@example.com> (domain example.com)
Return-Path: <bounce@example.com> (domain example.com)

Hops (oldest first): 4
  1. start    from localhost (localhost [192.0.2.1]) by app.example.com (Postfix, from userid 1000)
  2. +2 s     from app.example.com (app.example.com [198.51.100.7]) by mail.example.com (Postfix) with ESMTP
  3. +3 s     from mail.example.com (mail.example.com [192.0.2.10]) by mx.example.net (Postfix) with ESMTPS
  4. +6 s     from mx.example.net (mx.example.net. [192.0.2.20]) by inbox.example.net with ESMTPS
Total transit: 11 s

Authentication (verdict from mx.example.net): spf=pass dkim=pass dmarc=pass
  mx.example.net: dkim=pass header.i=@example.com header.d=example.com header.s=google header.b=aBcDeF12; spf=pass smtp.mailfrom=bounce@example.com; dmarc=pass header.from=example.com
Alignment: aligned
  DKIM d=example.com: relaxed yes, strict yes
  SPF domain example.com: relaxed yes, strict yes
DKIM-Signatures: 1
  d=example.com s=google a=rsa-sha256 c=relaxed/relaxed, From signed: yes

Findings
  (none)
```

And on a newsletter whose DKIM signature belongs to the bulk mailer rather than the From domain:

```
$ node bin/mailguard.ts headers test/fixtures/eml/misaligned-dkim.eml
From: Alice Example <alice@example.com> (domain example.com)
Return-Path: <bounces@bulk-mailer.net> (domain bulk-mailer.net)

Hops (oldest first): 2
  1. start    from campaign.bulk-mailer.net (campaign.bulk-mailer.net [203.0.113.9]) by out1.bulk-mailer.net (Postfix) with ESMTP
  2. +3 s     from out1.bulk-mailer.net (out1.bulk-mailer.net [203.0.113.5]) by mx.example.net (Postfix) with ESMTPS
Total transit: 3 s

Authentication (verdict from mx.example.net): spf=pass dkim=pass dmarc=fail
  mx.example.net: dkim=pass header.d=bulk-mailer.net header.s=bm1 header.b=ZyXwVu98; spf=pass smtp.mailfrom=bounces@bulk-mailer.net; dmarc=fail reason="No valid SPF, no valid DKIM" header.from=example.com
Alignment: misaligned
  DKIM d=bulk-mailer.net: relaxed no, strict no
  SPF domain bulk-mailer.net: relaxed no, strict no
DKIM-Signatures: 1
  d=bulk-mailer.net s=bm1 a=rsa-sha256 c=relaxed/simple, From signed: no

Findings
  [error] dmarc=fail in Authentication-Results from mx.example.net (No valid SPF, no valid DKIM)
  [warning] DKIM d=bulk-mailer.net does not align with the From domain example.com, even in relaxed mode
  [warning] SPF domain bulk-mailer.net (smtp.mailfrom or Return-Path) does not align with the From domain example.com, even in relaxed mode
  [warning] DKIM-Signature d=bulk-mailer.net s=bm1 does not cover the From header in its h= list
  [info] Return-Path domain bulk-mailer.net differs from the From domain example.com, which is common for bulk senders and bounce handling
```

## Grading

The `domain` command starts at 100 and subtracts points for each problem it finds. The table below is the whole rubric; it is the same table as `DEDUCTIONS` in `src/grade.ts`, and a test fails if the two ever differ.

| Finding id | Points | What it means |
| --- | --- | --- |
| `spf.plus-all` | -40 | The SPF record ends in `+all`, which authorizes every host on the internet. |
| `spf.missing` | -30 | No TXT record starting with `v=spf1`. |
| `spf.multiple` | -30 | More than one SPF record; receivers treat this as a permanent error. |
| `spf.syntax` | -30 | The record does not parse (unknown mechanism, bad qualifier, malformed CIDR, duplicate redirect). |
| `spf.loop` | -30 | An include or redirect chain comes back to a domain already on the path, or evaluation hit the 50-lookup safety cap. |
| `spf.question-all` | -20 | The record ends in `?all`, which is neutral and protects nothing. |
| `spf.lookups-over-10` | -25 | More than 10 DNS lookups are needed, so receivers return a permanent error. |
| `spf.lookups-8-to-10` | -5 | Between 8 and 10 lookups; still valid but one more include breaks it. |
| `spf.include-missing` | -10 | An `include:` or `redirect=` target has no SPF record. |
| `spf.no-all` | -5 | The record ends without an `all` mechanism or a redirect, so unlisted hosts get a neutral result. |
| `spf.ptr` | -5 | The record uses the `ptr` mechanism, which RFC 7208 says not to use. |
| `dmarc.missing` | -30 | No DMARC record at `_dmarc.<domain>` and none inherited from the organizational domain. |
| `dmarc.multiple` | -30 | More than one DMARC record. |
| `dmarc.invalid` | -30 | The record does not parse, or has no `p=` tag, or `v=DMARC1` is not first. |
| `dmarc.p-none` | -25 | The effective policy is `p=none`, so failing mail is only reported, never quarantined or rejected. |
| `dmarc.pct` | -5 | `pct=` is below 100, so only part of the failing mail gets the policy. |
| `dmarc.no-rua` | -5 | No `rua=` address, so nobody receives aggregate reports. |
| `dmarc.sp-weaker` | -5 | The subdomain policy `sp=` is weaker than `p=`. |
| `dkim.rsa-weak` | -10 | An RSA key shorter than 2048 bits was found under a probed selector. |
| `mx.missing-a-present` | -10 | No MX record; mail falls back to the A or AAAA address under the implicit MX rule. |
| `mx.missing-no-a` | -15 | No MX record and no A or AAAA record, so the domain cannot receive mail. |
| `mx.host-unresolvable` | -15 | An MX host has no A or AAAA record. |
| `mx.ip-literal` | -10 | An MX exchange is an IP address instead of a hostname, which RFC 5321 forbids. |

Every other finding id (`spf.record`, `dmarc.record`, `dmarc.inherited`, `dkim.found`, `dkim.none`, `dkim.revoked`, `dkim.unparseable`, `dkim.lookup-error`, `mx.null`, `mx.addresses`, the `*.lookup-error` warnings, and everything the `headers` command emits) deducts nothing. Each deduction id is applied at most once per audit no matter how many findings share it, so a domain with three weak DKIM keys loses 10 points, not 30. The score never goes below 0.

Grades: A is 90 or above, B is 80 to 89, C is 65 to 79, D is 50 to 64, F is below 50.

Worked examples: a domain with good SPF, DKIM and MX but `p=none` scores 100 - 25 = 75, a C. A domain with no SPF, no DMARC and no MX but an A record scores 100 - 30 - 30 - 10 = 30, an F. The all-good fixture scores 100, an A.

DKIM is never deducted for being absent, because the probe only guesses selector names. If your provider uses a selector that is not in the default list, pass it with `--selector`.

## Exit codes

| Code | domain | headers |
| --- | --- | --- |
| 0 | Grade A or B | At least one header parsed |
| 1 | Grade C, D or F | not used |
| 2 | Usage error, invalid domain, unreadable or malformed zone file, `--zone` combined with `--dns` or `--timeout`, the domain does not exist (NXDOMAIN for TXT, MX, A and AAAA), or the resolver is unreachable | Usage error, unreadable file, empty input, or no headers found |

The grade is the only thing that decides between 0 and 1, so a shell script can use `mailguard domain example.com --json && echo ok` as a pass/fail check.

## JSON output

With `--json`, stdout carries exactly one JSON document and nothing else. Identical DNS answers produce byte-identical output: findings are listed in check order (spf, dmarc, dkim, mx), DKIM selector results are sorted by selector name, and there are no timestamps or durations in a report.

`domain`:

```
{
  "domain": "example.com",
  "grade": "A" | "B" | "C" | "D" | "F",
  "score": 0..100,
  "checks": {
    "spf":   { "record", "records", "lookupCount", "allQualifier", "includes", "redirects" },
    "dmarc": { "record", "source", "inherited", "policy", "subdomainPolicy", "effectivePolicy", "pct", "rua" },
    "dkim":  { "probed": [selector...], "selectors": [{ "selector", "keyType", "bits", "revoked", "flags" }] },
    "mx":    { "nullMx", "records": [{ "priority", "exchange", "addresses" }] }
  },
  "findings": [{ "check", "id", "severity": "error" | "warning" | "info", "message" }]
}
```

`headers`:

```
{
  "from":       { "raw", "address", "domain" },
  "returnPath": { "raw", "address", "domain" },
  "hops": [{ "from", "by", "with", "id", "for", "date", "timestamp", "delaySeconds", "flags" }],
  "totalTransitSeconds": number | null,
  "authResults": [{ "authservId", "results": [{ "method", "result", "reason", "properties" }] }],
  "verdict":   { "authservId", "spf", "dkim", "dmarc" },
  "alignment": {
    "dkim": { "domain", "relaxed", "strict" },
    "spf":  { "domain", "relaxed", "strict" },
    "verdict": "aligned" | "misaligned" | "unknown"
  },
  "dkimSignatures": [{ "d", "s", "a", "c", "fromSigned" }],
  "findings": [{ "check", "id", "severity", "message" }]
}
```

Hops are listed oldest first. `delaySeconds` is the gap from the previous hop and is `null` for the first hop or when either date could not be parsed. Hop flags are `clock-skew` (negative delay), `slow` (more than 300 seconds) and `no-date`. `totalTransitSeconds` is the sum of the delays that could be computed, or `null` if none could. The verdict comes from the topmost Authentication-Results header; every Authentication-Results header is listed in `authResults` in header order with its authserv-id. Alignment compares the From domain with the DKIM `header.d` (falling back to the first DKIM-Signature `d=`) and with `smtp.mailfrom` (falling back to the Return-Path domain), in relaxed mode (same organizational domain) and strict mode (exact match); `alignment.verdict` is `aligned` when either relaxed comparison passes.

## Default DKIM selectors

The probe always queries these 20 selectors, in this order, plus anything given with `--selector`:

`default`, `google`, `selector1`, `selector2`, `k1`, `k2`, `k3`, `s1`, `s2`, `dkim`, `mail`, `smtp`, `mandrill`, `pm`, `zoho`, `fm1`, `fm2`, `fm3`, `protonmail`, `mailo`

For each key found it reports the key type and size. RSA keys are decoded with `node:crypto` to read the modulus length; keys shorter than 2048 bits are flagged. Ed25519 keys (RFC 8463) are recognized by their 32-byte raw form and reported as 256 bits. A record with an empty `p=` is reported as revoked. Five selectors are queried at a time.

## Organizational domain limitation

mailguard finds the organizational domain by keeping the last two labels of a name: `mail.example.com` becomes `example.com`. It does not bundle the Public Suffix List, so this is wrong for domains under a two-label public suffix such as `co.uk`, `com.au` or `co.jp`, where `mail.example.co.uk` should map to `example.co.uk` but is mapped to `co.uk`. This affects two things: the DMARC fallback lookup for a subdomain, and relaxed alignment in the `headers` command. The `dmarc.inherited` message and the alignment output always name the domain that was actually consulted, so the mistake is visible when it happens.

## What it does not do

- It does not verify DKIM signatures. The `headers` command reports the `d=`, `s=`, `a=`, `c=` and `h=` values of each DKIM-Signature header and what the receiver's Authentication-Results said; it does not fetch keys or check the `b=` value.
- It does not evaluate SPF against a sending IP address. The `domain` command checks the record's syntax, lookup count and `all` qualifier; it does not tell you whether a particular server is authorized.
- It does not expand SPF macros (`%{i}`, `%{s}` and so on). Terms containing macros are counted and kept as written.
- It does not resolve `a`, `mx`, `ptr` or `exists` targets inside an SPF record; they are counted toward the lookup limit only.
- It does not bundle the Public Suffix List (see the section above).
- It does not check BIMI, MTA-STS, TLS-RPT, DANE, DNSSEC, ARC or Received-SPF headers.
- It does not send test messages, connect to mail servers on port 25, or check TLS on MX hosts.
- It does not read the message body and does not run any DNS query from the `headers` command.
- It does not print colors, and it does not print timestamps or timing information in reports.
- It does not run as a server or watch anything; every invocation is a single audit that exits.

## Development and tests

```sh
npm test
```

`npm test` runs `tsc --noEmit` and then `node --test test/*.test.ts`. The tests never touch the network: DNS answers come from the zone fixtures in `test/fixtures/zones` and from in-memory fake resolvers, and the header fixtures live in `test/fixtures/eml` (kept byte-exact with CRLF endings through `.gitattributes`). A hygiene test asserts that `node:dns` is imported only by `src/resolver.ts`, that the repo contains no leftover work markers, phone numbers, real email addresses or secret-shaped strings, and that this README's grading table and section order match the code. The suite has been run with the network namespace removed (`unshare -rn npm test`) to prove that claim.

The only development dependencies are `typescript` (for `tsc --noEmit`) and `@types/node` (`tsc` cannot resolve `node:dns` or `node:crypto` without it). There are no runtime dependencies. Node executes the TypeScript sources directly through its built-in type stripping, so the code uses only erasable syntax: no enums, namespaces, parameter properties or decorators. Some Node 24 minor versions print an ExperimentalWarning about type stripping on stderr; it is harmless and the CLI tests ignore it.

DKIM keys in the fixtures are real public keys generated once offline with `node:crypto`; no private key exists anywhere in the repo. Fixtures use only the `example.com`, `example.net` and `example.org` domains (plus `bulk-mailer.net` for the misalignment case) and documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).

Continuous integration runs the same `npm test` on Node 24 and Node 26 through GitHub Actions (`.github/workflows/ci.yml`).

## License

MIT. See `LICENSE`.
