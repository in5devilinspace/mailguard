import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditDomain } from '../src/audit.ts';
import { exitCodeForGrade, scoreFindings } from '../src/grade.ts';
import { zoneResolver } from '../src/zone.ts';
import { DomainNotFoundError } from '../src/types.ts';
import { loadZone, spyResolver, throwingResolver } from './helpers.ts';

const run = (zone: string, domain = 'example.com') => auditDomain(domain, zoneResolver(loadZone(zone)));

test('all-good scores 100 and grades A with exit 0', async () => {
  const report = await run('all-good');
  assert.equal(report.domain, 'example.com');
  assert.equal(report.score, 100);
  assert.equal(report.grade, 'A');
  assert.equal(exitCodeForGrade(report.grade), 0);
  assert.equal(report.findings.every((f) => f.severity === 'info'), true);
});

test('nothing-configured scores 30 and grades F with exit 1', async () => {
  const report = await run('nothing-configured');
  assert.equal(report.score, 30);
  assert.equal(report.grade, 'F');
  assert.equal(exitCodeForGrade(report.grade), 1);
});

test('dmarc-missing scores 70 (C) and dmarc-p-none exactly 75 (C)', async () => {
  const missing = await run('dmarc-missing');
  assert.deepEqual([missing.score, missing.grade], [70, 'C']);
  const none = await run('dmarc-p-none');
  assert.deepEqual([none.score, none.grade], [75, 'C']);
});

test('nxdomain zone rejects with DomainNotFoundError; total resolver failure does not', async () => {
  await assert.rejects(run('nxdomain'), DomainNotFoundError);
  const report = await auditDomain('example.com', throwingResolver('ETIMEOUT'));
  assert.equal(report.findings.filter((f) => f.id.endsWith('lookup-error')).length >= 3, true);
});

test('findings come in spf, dmarc, dkim, mx order and are well formed', async () => {
  const report = await run('nothing-configured');
  const order = ['spf', 'dmarc', 'dkim', 'mx'];
  const seen = report.findings.map((f) => order.indexOf(f.check));
  assert.deepEqual(seen, [...seen].sort((a, b) => a - b));
  assert.equal(new Set(report.findings.map((f) => f.check)).size, 4);
  for (const finding of report.findings) {
    assert.ok(['error', 'warning', 'info'].includes(finding.severity));
    assert.ok(finding.id.startsWith(finding.check + '.'));
    assert.ok(finding.message.length > 0);
    assert.equal(finding.message.includes('—'), false);
  }
});

test('two runs are deep-equal and check summaries carry no findings arrays', async () => {
  const [first, second] = await Promise.all([run('all-good'), run('all-good')]);
  assert.deepEqual(first, second);
  for (const summary of Object.values(first.checks)) {
    assert.equal('findings' in summary, false);
  }
  assert.deepEqual(Object.keys(first.checks), ['spf', 'dmarc', 'dkim', 'mx']);
});

test('dkim-none and dkim-google-2048 score the same (no DKIM deduction)', async () => {
  const none = await run('dkim-none');
  const found = await run('dkim-google-2048');
  assert.deepEqual(scoreFindings(none.findings), scoreFindings(found.findings));
});

test('auditDomain passes extra selectors through and queries each apex type once', async () => {
  const spy = spyResolver(zoneResolver(loadZone('all-good')));
  const report = await auditDomain('example.com', spy.resolver, { selectors: ['custom1'] });
  assert.ok(report.checks.dkim.probed.includes('custom1'));
  assert.ok(spy.queries.some((q) => q.name === 'custom1._domainkey.example.com'));
  assert.equal(spy.queries.filter((q) => q.type === 'TXT' && q.name === 'example.com').length, 1);
  assert.equal(spy.queries.filter((q) => q.type === 'MX' && q.name === 'example.com').length, 1);
});
