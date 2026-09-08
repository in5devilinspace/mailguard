import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditDomain } from '../src/audit.ts';
import { auditExtras, parseBimi, parseMtaSts, parseTlsRpt } from '../src/extras.ts';
import { scoreFindings } from '../src/grade.ts';
import { zoneResolver } from '../src/zone.ts';
import type { Finding } from '../src/types.ts';
import { loadZone, spyResolver, throwingResolver, variant } from './helpers.ts';

const byId = (findings: Finding[], id: string) => findings.filter((f) => f.id === id);

test('parseBimi, parseMtaSts and parseTlsRpt read tags and reject records missing required tags', () => {
  assert.deepEqual(parseBimi('v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem'), {
    location: 'https://example.com/logo.svg',
    authority: 'https://example.com/vmc.pem',
    error: null,
  });
  assert.deepEqual(parseBimi('v=BIMI1; l=;'), { location: '', authority: null, error: null });
  assert.equal(parseBimi('v=BIMI1; a=https://example.com/vmc.pem').error, 'record has no l tag');
  assert.equal(parseBimi('l=https://example.com/logo.svg; v=BIMI1').error, 'v=BIMI1 must be the first tag');

  assert.deepEqual(parseMtaSts('v=STSv1; id=20250701'), { id: '20250701', error: null });
  assert.equal(parseMtaSts('v=STSv1').error, 'record has no id tag');

  assert.deepEqual(parseTlsRpt('v=TLSRPTv1; rua=mailto:tls@example.com,https://example.com/tlsrpt'), {
    rua: ['mailto:tls@example.com', 'https://example.com/tlsrpt'],
    error: null,
  });
  assert.equal(parseTlsRpt('v=TLSRPTv1; rua=').error, 'record has no rua tag');
});

test('all-good publishes BIMI, MTA-STS and TLS-RPT: three info findings, nothing graded', async () => {
  const result = await auditExtras('example.com', zoneResolver(loadZone('all-good')));
  assert.deepEqual(result.bimi, {
    record: 'v=BIMI1; l=https://example.com/brand/logo.svg; a=https://example.com/brand/vmc.pem',
    location: 'https://example.com/brand/logo.svg',
    authority: 'https://example.com/brand/vmc.pem',
  });
  assert.deepEqual(result.mtaSts, { record: 'v=STSv1; id=20250701', id: '20250701' });
  assert.deepEqual(result.tlsRpt, { record: 'v=TLSRPTv1; rua=mailto:tlsrpt@example.com', rua: ['mailto:tlsrpt@example.com'] });
  assert.deepEqual(result.findings.map((f) => f.id), ['extras.bimi-found', 'extras.mta-sts-found', 'extras.tls-rpt-found']);
  assert.equal(result.findings.every((f) => f.severity === 'info' && f.check === 'extras'), true);
  assert.match(byId(result.findings, 'extras.bimi-found')[0]?.message ?? '', /logo\.svg/);
  assert.match(byId(result.findings, 'extras.mta-sts-found')[0]?.message ?? '', /20250701/);
  assert.match(byId(result.findings, 'extras.tls-rpt-found')[0]?.message ?? '', /tlsrpt@example\.com/);
  assert.equal(scoreFindings(result.findings).score, 100);
});

test('nothing-configured reports each missing record as info naming the protocol', async () => {
  const result = await auditExtras('example.com', zoneResolver(loadZone('nothing-configured')));
  assert.deepEqual(result.findings.map((f) => f.id), ['extras.bimi-none', 'extras.mta-sts-none', 'extras.tls-rpt-none']);
  assert.match(byId(result.findings, 'extras.bimi-none')[0]?.message ?? '', /BIMI/);
  assert.match(byId(result.findings, 'extras.mta-sts-none')[0]?.message ?? '', /MTA-STS/);
  assert.match(byId(result.findings, 'extras.tls-rpt-none')[0]?.message ?? '', /TLS-RPT/);
  assert.equal(result.findings.every((f) => f.severity === 'info'), true);
  assert.deepEqual(result.bimi, { record: null, location: null, authority: null });
  assert.deepEqual(result.mtaSts, { record: null, id: null });
  assert.deepEqual(result.tlsRpt, { record: null, rua: [] });
});

test('malformed and duplicate records are reported as info, never as deductions', async () => {
  const zone = variant(loadZone('all-good'), {
    'default._bimi.example.com': { TXT: ['v=BIMI1; a=https://example.com/brand/vmc.pem'] },
    '_mta-sts.example.com': { TXT: ['v=STSv1', 'v=STSv1; id=1'] },
    '_smtp._tls.example.com': { TXT: ['v=TLSRPTv1', 'unrelated=1'] },
  });
  const result = await auditExtras('example.com', zoneResolver(zone));
  assert.deepEqual(result.findings.map((f) => f.id), ['extras.bimi-invalid', 'extras.mta-sts-multiple', 'extras.tls-rpt-invalid']);
  assert.match(byId(result.findings, 'extras.bimi-invalid')[0]?.message ?? '', /no l tag/);
  assert.match(byId(result.findings, 'extras.mta-sts-multiple')[0]?.message ?? '', /2/);
  assert.match(byId(result.findings, 'extras.tls-rpt-invalid')[0]?.message ?? '', /no rua tag/);
  assert.equal(result.findings.every((f) => f.severity === 'info'), true);
  assert.equal(scoreFindings(result.findings).score, 100);
  assert.equal(result.bimi.location, null);
  assert.equal(result.mtaSts.id, null);
});

test('a resolver error becomes one extras.lookup-error info per protocol naming the DNS code', async () => {
  const result = await auditExtras('example.com', throwingResolver('ETIMEOUT'));
  const errors = byId(result.findings, 'extras.lookup-error');
  assert.equal(errors.length, 3);
  for (const finding of errors) {
    assert.equal(finding.severity, 'info');
    assert.match(finding.message, /ETIMEOUT/);
  }
});

test('auditExtras queries exactly three TXT names and nothing else', async () => {
  const spy = spyResolver(zoneResolver(loadZone('all-good')));
  await auditExtras('example.com', spy.resolver);
  assert.deepEqual(spy.queries, [
    { type: 'TXT', name: 'default._bimi.example.com' },
    { type: 'TXT', name: '_mta-sts.example.com' },
    { type: 'TXT', name: '_smtp._tls.example.com' },
  ]);
});

test('auditDomain carries checks.extras and lists extras findings after mx', async () => {
  const report = await auditDomain('example.com', zoneResolver(loadZone('all-good')));
  assert.deepEqual(Object.keys(report.checks), ['spf', 'dmarc', 'dkim', 'mx', 'extras']);
  assert.equal(report.checks.extras.mtaSts.id, '20250701');
  assert.equal('findings' in report.checks.extras, false);
  const lastMx = report.findings.map((f) => f.check).lastIndexOf('mx');
  const firstExtras = report.findings.map((f) => f.check).indexOf('extras');
  assert.ok(firstExtras > lastMx);
  assert.equal(report.score, 100);
});
