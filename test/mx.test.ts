import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditMx, isIpLiteral } from '../src/mx.ts';
import { zoneResolver } from '../src/zone.ts';
import type { Finding } from '../src/types.ts';
import { DnsError } from '../src/types.ts';
import { loadZone, spyResolver, throwingResolver, variant } from './helpers.ts';

const byId = (findings: Finding[], id: string) => findings.filter((f) => f.id === id);

test('isIpLiteral recognizes dotted and bracketed IPv4 and IPv6', () => {
  assert.equal(isIpLiteral('192.0.2.10'), true);
  assert.equal(isIpLiteral('[192.0.2.11]'), true);
  assert.equal(isIpLiteral('[2001:db8::1]'), true);
  assert.equal(isIpLiteral('2001:db8::1'), true);
  assert.equal(isIpLiteral('mx.example.com'), false);
  assert.equal(isIpLiteral('.'), false);
});

test('auditMx all-good: records sorted by priority with address counts', async () => {
  const result = await auditMx('example.com', zoneResolver(loadZone('all-good')));
  assert.equal(result.nullMx, false);
  assert.deepEqual(result.records, [
    { priority: 10, exchange: 'mx1.example.com', addresses: ['192.0.2.10', '2001:db8::10'] },
    { priority: 20, exchange: 'mx2.example.com', addresses: ['192.0.2.11'] },
  ]);
  const infos = byId(result.findings, 'mx.addresses');
  assert.equal(infos.length, 2);
  assert.match(infos[0]?.message ?? '', /mx1\.example\.com/);
  assert.match(infos[0]?.message ?? '', /2 address/);
  assert.match(infos[1]?.message ?? '', /1 address/);
  assert.equal(result.findings.every((f) => f.severity === 'info'), true);
});

test('auditMx null MX: info containing "does not accept mail" and no host findings', async () => {
  const result = await auditMx('example.com', zoneResolver(loadZone('mx-null')));
  assert.equal(result.nullMx, true);
  assert.deepEqual(result.records, [{ priority: 0, exchange: '.', addresses: [] }]);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0]?.id, 'mx.null');
  assert.match(result.findings[0]?.message ?? '', /does not accept mail/);
});

test('auditMx flags an MX host with no address', async () => {
  const result = await auditMx('example.com', zoneResolver(loadZone('mx-no-address')));
  const finding = byId(result.findings, 'mx.host-unresolvable')[0];
  assert.equal(finding?.severity, 'error');
  assert.match(finding?.message ?? '', /mx\.example\.com/);
});

test('auditMx flags IP literal exchanges', async () => {
  const spy = spyResolver(zoneResolver(loadZone('mx-ip-literal')));
  const result = await auditMx('example.com', spy.resolver);
  const findings = byId(result.findings, 'mx.ip-literal');
  assert.equal(findings.length, 2);
  assert.match(findings[0]?.message ?? '', /IP literal/);
  assert.match(findings[0]?.message ?? '', /192\.0\.2\.10/);
  assert.match(findings[1]?.message ?? '', /\[192\.0\.2\.11\]/);
  assert.deepEqual(spy.queries, [{ type: 'MX', name: 'example.com' }]);
});

test('auditMx missing MX falls back to the apex address or errors', async () => {
  const present = await auditMx('example.com', zoneResolver(loadZone('mx-missing-a-present')));
  assert.deepEqual(present.records, []);
  const warn = byId(present.findings, 'mx.missing-a-present')[0];
  assert.equal(warn?.severity, 'warning');
  assert.match(warn?.message ?? '', /no MX/);

  const none = await auditMx('example.com', zoneResolver(variant(loadZone('mx-missing-a-present'), { 'example.com': { A: [], AAAA: [] } })));
  const error = byId(none.findings, 'mx.missing-no-a')[0];
  assert.equal(error?.severity, 'error');
  assert.match(error?.message ?? '', /no MX/);
  assert.match(error?.message ?? '', /cannot receive mail/);
});

test('auditMx reports resolver errors as findings instead of throwing', async () => {
  const result = await auditMx('example.com', throwingResolver('ETIMEOUT'));
  assert.deepEqual(result.records, []);
  assert.match(byId(result.findings, 'mx.lookup-error')[0]?.message ?? '', /ETIMEOUT/);

  const inner = zoneResolver(loadZone('all-good'));
  const flaky = { ...inner, resolve4: (name: string) => (name === 'mx2.example.com' ? Promise.reject(new DnsError('ESERVFAIL')) : inner.resolve4(name)) };
  const partial = await auditMx('example.com', flaky);
  assert.deepEqual(partial.records[0]?.addresses, ['192.0.2.10', '2001:db8::10']);
  const warn = byId(partial.findings, 'mx.lookup-error')[0];
  assert.equal(warn?.severity, 'warning');
  assert.match(warn?.message ?? '', /mx2\.example\.com/);
  assert.match(warn?.message ?? '', /ESERVFAIL/);
  assert.equal(byId(partial.findings, 'mx.host-unresolvable').length, 1);
});
