import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditSpf, parseSpf } from '../src/spf.ts';
import type { Finding } from '../src/types.ts';
import { zoneResolver } from '../src/zone.ts';
import { loadZone, spyResolver, throwingResolver, variant } from './helpers.ts';

test('parseSpf reads every mechanism, qualifier and modifier', () => {
  const parsed = parseSpf('v=spf1 a mx:mail.example.com include:_spf.example.com ip4:192.0.2.0/24 ip6:2001:db8::/32 exists:%{i}.example.com ptr ~all');
  assert.equal(parsed.error, null);
  assert.deepEqual(parsed.mechanisms.map((m) => [m.qualifier, m.type, m.value]), [
    ['+', 'a', null],
    ['+', 'mx', 'mail.example.com'],
    ['+', 'include', '_spf.example.com'],
    ['+', 'ip4', '192.0.2.0/24'],
    ['+', 'ip6', '2001:db8::/32'],
    ['+', 'exists', '%{i}.example.com'],
    ['+', 'ptr', null],
    ['~', 'all', null],
  ]);
  const qualified = parseSpf('v=spf1 -a +mx ?include:x.example.com -all');
  assert.deepEqual(qualified.mechanisms.map((m) => m.qualifier), ['-', '+', '?', '-']);
  const mods = parseSpf('v=spf1 redirect=_spf.example.com exp=explain.example.com custom=ignored');
  assert.equal(mods.error, null);
  assert.deepEqual(mods.modifiers, [
    { name: 'redirect', value: '_spf.example.com' },
    { name: 'exp', value: 'explain.example.com' },
  ]);
  assert.equal(parseSpf('V=SPF1 -all').error, null);
});

test('parseSpf reports syntax errors', () => {
  assert.match(parseSpf('v=spf1 bogus -all').error ?? '', /bogus/);
  assert.match(parseSpf('v=spf1 ip4:192.0.2.0/40 -all').error ?? '', /ip4/);
  assert.match(parseSpf('v=spf1 ip4:999.0.0.1 -all').error ?? '', /ip4/);
  assert.match(parseSpf('v=spf1 ip6:zzzz -all').error ?? '', /ip6/);
  assert.match(parseSpf('v=spf1 include -all').error ?? '', /include/);
  assert.match(parseSpf('v=spf1 redirect=a.example.com redirect=b.example.com').error ?? '', /redirect/);
  assert.match(parseSpf('v=spf2 -all').error ?? '', /v=spf1/);
  assert.match(parseSpf('v=spf1 *all').error ?? '', /\*all/);
});

async function audit(zoneName: string, domain = 'example.com') {
  return auditSpf(domain, zoneResolver(loadZone(zoneName)));
}
const byId = (findings: Finding[], id: string) => findings.filter((f) => f.id === id);

test('auditSpf all-good: one lookup, -all, info record, no warnings', async () => {
  const result = await audit('all-good');
  assert.equal(result.record, 'v=spf1 include:_spf.example.com -all');
  assert.equal(result.lookupCount, 1);
  assert.equal(result.allQualifier, '-');
  assert.deepEqual(result.includes, ['_spf.example.com']);
  assert.deepEqual(result.findings.map((f) => f.severity), ['info']);
  assert.equal(result.findings[0]?.id, 'spf.record');
  assert.match(result.findings[0]?.message ?? '', /v=spf1 include:_spf\.example\.com -all/);
});

test('auditSpf counts an include chain of 11 and flags the 10 DNS lookups limit', async () => {
  const result = await audit('spf-too-many-lookups');
  assert.equal(result.lookupCount, 11);
  const over = byId(result.findings, 'spf.lookups-over-10');
  assert.equal(over.length, 1);
  assert.equal(over[0]?.severity, 'error');
  assert.match(over[0]?.message ?? '', /10 DNS lookups/);
  assert.match(over[0]?.message ?? '', /11/);
});

test('auditSpf warns between 8 and 10 lookups', async () => {
  const zone = variant(loadZone('spf-too-many-lookups'), { '_spf3.example.com': { TXT: ['v=spf1 a -all'] } });
  const result = await auditSpf('example.com', zoneResolver(zone));
  assert.equal(result.lookupCount, 9);
  assert.equal(byId(result.findings, 'spf.lookups-over-10').length, 0);
  const warn = byId(result.findings, 'spf.lookups-8-to-10');
  assert.equal(warn[0]?.severity, 'warning');
  assert.match(warn[0]?.message ?? '', /9/);
});

test('auditSpf flags +all, ?all, ptr and a missing all', async () => {
  const plus = await audit('spf-plus-all');
  assert.equal(plus.allQualifier, '+');
  assert.match(byId(plus.findings, 'spf.plus-all')[0]?.message ?? '', /\+all/);
  assert.equal(byId(plus.findings, 'spf.plus-all')[0]?.severity, 'error');

  const question = await auditSpf('example.com', zoneResolver(variant(loadZone('all-good'), { 'example.com': { TXT: ['v=spf1 ip4:192.0.2.0/24 ?all'] } })));
  assert.equal(byId(question.findings, 'spf.question-all')[0]?.severity, 'warning');

  const ptr = await auditSpf('example.com', zoneResolver(variant(loadZone('all-good'), { 'example.com': { TXT: ['v=spf1 ptr -all'] } })));
  assert.equal(byId(ptr.findings, 'spf.ptr')[0]?.severity, 'warning');
  assert.equal(ptr.lookupCount, 1);

  const noAll = await auditSpf('example.com', zoneResolver(variant(loadZone('all-good'), { 'example.com': { TXT: ['v=spf1 ip4:192.0.2.0/24'] } })));
  assert.equal(noAll.allQualifier, null);
  assert.equal(byId(noAll.findings, 'spf.no-all')[0]?.severity, 'warning');
});

test('auditSpf flags a missing record, multiple records and syntax errors', async () => {
  const missing = await audit('nothing-configured');
  assert.equal(missing.record, null);
  assert.equal(byId(missing.findings, 'spf.missing')[0]?.severity, 'error');

  const two = await audit('spf-two-records');
  assert.equal(two.records.length, 2);
  assert.match(byId(two.findings, 'spf.multiple')[0]?.message ?? '', /multiple SPF records/);

  const syntax = await auditSpf('example.com', zoneResolver(variant(loadZone('all-good'), { 'example.com': { TXT: ['v=spf1 ip4:192.0.2.0/40 -all'] } })));
  assert.equal(byId(syntax.findings, 'spf.syntax')[0]?.severity, 'error');
});

test('auditSpf terminates on redirect and include loops with a loop error', async () => {
  const redirect = await audit('spf-redirect-loop');
  const loop = byId(redirect.findings, 'spf.loop');
  assert.equal(loop.length, 1);
  assert.match(loop[0]?.message ?? '', /loop/);
  assert.match(loop[0]?.message ?? '', /other\.example\.com/);

  const zone = variant(loadZone('all-good'), {
    'example.com': { TXT: ['v=spf1 include:a.example.com -all'] },
    'a.example.com': { TXT: ['v=spf1 include:b.example.com -all'] },
    'b.example.com': { TXT: ['v=spf1 include:a.example.com -all'] },
  });
  const include = await auditSpf('example.com', zoneResolver(zone));
  assert.match(byId(include.findings, 'spf.loop')[0]?.message ?? '', /loop/);
});

test('auditSpf names a missing include target and reports resolver errors as findings', async () => {
  const missing = await audit('spf-include-missing');
  const finding = byId(missing.findings, 'spf.include-missing')[0];
  assert.equal(finding?.severity, 'error');
  assert.match(finding?.message ?? '', /_spf\.missing\.example\.com/);

  const failing = await auditSpf('example.com', throwingResolver('ETIMEOUT'));
  assert.equal(failing.record, null);
  assert.match(byId(failing.findings, 'spf.lookup-error')[0]?.message ?? '', /ETIMEOUT/);
});

test('auditSpf only queries TXT for the domain, include targets and redirect targets', async () => {
  const zone = variant(loadZone('spf-too-many-lookups'), {
    'example.com': { TXT: ['v=spf1 a mx:mail.example.com exists:x.example.com include:_spf1.example.com redirect=_spf2.example.com'] },
  });
  const spy = spyResolver(zoneResolver(zone));
  const result = await auditSpf('example.com', spy.resolver);
  // top: a, mx, exists, include, redirect (5); _spf1: a, mx, include (3); _spf2: a, mx (2)
  assert.equal(result.lookupCount, 10);
  assert.deepEqual(result.redirects, ['_spf2.example.com']);
  assert.deepEqual(spy.queries, [
    { type: 'TXT', name: 'example.com' },
    { type: 'TXT', name: '_spf1.example.com' },
    { type: 'TXT', name: '_deep.example.com' },
    { type: 'TXT', name: '_spf2.example.com' },
  ]);
});
