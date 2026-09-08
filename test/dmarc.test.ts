import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditDmarc, organizationalDomain, parseDmarc } from '../src/dmarc.ts';
import { zoneResolver } from '../src/zone.ts';
import type { Finding } from '../src/types.ts';
import { loadZone, throwingResolver, variant } from './helpers.ts';

const byId = (findings: Finding[], id: string) => findings.filter((f) => f.id === id);

test('parseDmarc applies defaults and reads every tag', () => {
  const parsed = parseDmarc('v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:a@example.com,mailto:b@example.com; ruf=mailto:f@example.com; adkim=s; aspf=r; fo=1; ri=3600; rf=afrf');
  assert.equal(parsed.error, null);
  assert.equal(parsed.p, 'reject');
  assert.equal(parsed.sp, 'quarantine');
  assert.equal(parsed.pct, 50);
  assert.deepEqual(parsed.rua, ['mailto:a@example.com', 'mailto:b@example.com']);
  assert.deepEqual(parsed.ruf, ['mailto:f@example.com']);
  assert.equal(parsed.adkim, 's');
  assert.equal(parsed.aspf, 'r');
  assert.equal(parsed.fo, '1');
  assert.equal(parsed.ri, '3600');
  assert.equal(parsed.rf, 'afrf');
  const minimal = parseDmarc('v=DMARC1; p=none');
  assert.equal(minimal.pct, 100);
  assert.equal(minimal.sp, null);
  assert.equal(minimal.adkim, 'r');
  assert.equal(minimal.aspf, 'r');
  assert.deepEqual(minimal.rua, []);
  assert.equal(parseDmarc('v=DMARC1;p=REJECT').p, 'reject');
});

test('parseDmarc rejects bad records', () => {
  assert.match(parseDmarc('p=none; v=DMARC1').error ?? '', /v=DMARC1 must be the first tag/);
  assert.match(parseDmarc('v=DMARC1; rua=mailto:x@example.com').error ?? '', /p tag/);
  assert.match(parseDmarc('v=DMARC1; p=block').error ?? '', /p=block/);
  assert.match(parseDmarc('v=DMARC1; p=none; sp=maybe').error ?? '', /sp=maybe/);
  assert.match(parseDmarc('v=DMARC1; p=none; pct=150').error ?? '', /pct/);
  assert.match(parseDmarc('v=DMARC1; p=none; pct=abc').error ?? '', /pct/);
  assert.match(parseDmarc('v=spf1 -all').error ?? '', /v=DMARC1/);
});

test('organizationalDomain strips down to two labels', () => {
  assert.equal(organizationalDomain('a.b.example.com'), 'example.com');
  assert.equal(organizationalDomain('example.com'), 'example.com');
  assert.equal(organizationalDomain('localhost'), 'localhost');
  assert.equal(organizationalDomain('Mail.Example.COM'), 'example.com');
});

async function audit(zoneName: string, domain = 'example.com') {
  return auditDmarc(domain, zoneResolver(loadZone(zoneName)));
}

test('auditDmarc all-good: p=reject with rua, info only', async () => {
  const result = await audit('all-good');
  assert.equal(result.inherited, false);
  assert.equal(result.source, 'example.com');
  assert.equal(result.policy, 'reject');
  assert.equal(result.effectivePolicy, 'reject');
  assert.deepEqual(result.findings.map((f) => f.id), ['dmarc.record']);
});

test('auditDmarc flags a missing record', async () => {
  const result = await audit('dmarc-missing');
  assert.equal(result.record, null);
  assert.equal(byId(result.findings, 'dmarc.missing')[0]?.severity, 'error');
  assert.match(byId(result.findings, 'dmarc.missing')[0]?.message ?? '', /_dmarc\.example\.com/);
});

test('auditDmarc warns on p=none and pct below 100', async () => {
  const none = await audit('dmarc-p-none');
  assert.equal(none.effectivePolicy, 'none');
  const warning = byId(none.findings, 'dmarc.p-none')[0];
  assert.equal(warning?.severity, 'warning');
  assert.match(warning?.message ?? '', /p=none/);

  const pct = await audit('dmarc-reject-pct50');
  assert.match(byId(pct.findings, 'dmarc.pct')[0]?.message ?? '', /pct=50/);
  assert.equal(pct.pct, 50);
});

test('auditDmarc falls back to the organizational domain for subdomains', async () => {
  const result = await audit('dmarc-subdomain', 'mail.example.com');
  assert.equal(result.inherited, true);
  assert.equal(result.source, 'example.com');
  assert.equal(result.policy, 'reject');
  assert.equal(result.subdomainPolicy, 'quarantine');
  assert.equal(result.effectivePolicy, 'quarantine');
  const info = byId(result.findings, 'dmarc.inherited')[0];
  assert.equal(info?.severity, 'info');
  assert.match(info?.message ?? '', /mail\.example\.com/);
  assert.match(info?.message ?? '', /_dmarc\.example\.com/);
  assert.match(info?.message ?? '', /quarantine/);
  assert.equal(byId(result.findings, 'dmarc.sp-weaker')[0]?.severity, 'warning');
  assert.equal(byId(result.findings, 'dmarc.p-none').length, 0);
});

test('auditDmarc flags no rua, two records, invalid p, and reports resolver errors', async () => {
  const noRua = await auditDmarc('example.com', zoneResolver(variant(loadZone('all-good'), { '_dmarc.example.com': { TXT: ['v=DMARC1; p=reject'] } })));
  assert.equal(byId(noRua.findings, 'dmarc.no-rua')[0]?.severity, 'warning');

  const two = await auditDmarc('example.com', zoneResolver(variant(loadZone('all-good'), { '_dmarc.example.com': { TXT: ['v=DMARC1; p=reject', 'v=DMARC1; p=none'] } })));
  assert.equal(byId(two.findings, 'dmarc.multiple')[0]?.severity, 'error');
  assert.equal(two.policy, null);

  const invalid = await auditDmarc('example.com', zoneResolver(variant(loadZone('all-good'), { '_dmarc.example.com': { TXT: ['v=DMARC1; p=block; rua=mailto:d@example.com'] } })));
  assert.equal(byId(invalid.findings, 'dmarc.invalid')[0]?.severity, 'error');

  const missingP = await auditDmarc('example.com', zoneResolver(variant(loadZone('all-good'), { '_dmarc.example.com': { TXT: ['v=DMARC1; rua=mailto:d@example.com'] } })));
  assert.match(byId(missingP.findings, 'dmarc.invalid')[0]?.message ?? '', /p tag/);

  const ignored = await auditDmarc('example.com', zoneResolver(variant(loadZone('all-good'), { '_dmarc.example.com': { TXT: ['google-site-verification=xyz', 'v=DMARC1; p=reject; rua=mailto:d@example.com'] } })));
  assert.equal(ignored.policy, 'reject');

  const failing = await auditDmarc('example.com', throwingResolver('ESERVFAIL'));
  assert.match(byId(failing.findings, 'dmarc.lookup-error')[0]?.message ?? '', /ESERVFAIL/);
});
