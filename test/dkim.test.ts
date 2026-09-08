import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_SELECTORS, describeKey, parseDkimKey, probeDkim } from '../src/dkim.ts';
import { zoneResolver } from '../src/zone.ts';
import type { Finding, Resolver } from '../src/types.ts';
import { DnsError } from '../src/types.ts';
import { loadZone, spyResolver, throwingResolver, variant } from './helpers.ts';

// Fixture keys were generated once, offline, with:
// node -e "const {generateKeyPairSync}=require('node:crypto');console.log(generateKeyPairSync('rsa',{modulusLength:2048}).publicKey.export({type:'spki',format:'der'}).toString('base64'))"
// (1024 likewise; ed25519 raw key = spki.subarray(12).toString('base64')).

const byId = (findings: Finding[], id: string) => findings.filter((f) => f.id === id);

function fixtureRecord(zone: string, name: string): string {
  const txt = loadZone(zone)[name]?.TXT?.[0];
  assert.ok(txt !== undefined, `${zone} lacks ${name}`);
  return Array.isArray(txt) ? txt.join('') : txt;
}

test('parseDkimKey reads tags, defaults k to rsa and detects revoked keys', () => {
  const parsed = parseDkimKey('v=DKIM1; k=rsa; t=y:s; h=sha256; n=note; s=email; p=AAAA');
  assert.equal(parsed.error, null);
  assert.equal(parsed.k, 'rsa');
  assert.deepEqual(parsed.t, ['y', 's']);
  assert.equal(parsed.h, 'sha256');
  assert.equal(parsed.n, 'note');
  assert.equal(parsed.s, 'email');
  assert.equal(parsed.p, 'AAAA');
  assert.equal(parsed.revoked, false);
  const noVersion = parseDkimKey('p=AAAA');
  assert.equal(noVersion.error, null);
  assert.equal(noVersion.k, 'rsa');
  assert.equal(parseDkimKey('v=DKIM1; k=rsa; p=').revoked, true);
  assert.equal(parseDkimKey('v=DKIM1; p=AA AA\tAA').p, 'AAAAAA');
  assert.match(parseDkimKey('v=DKIM2; p=AAAA').error ?? '', /DKIM1/);
  assert.match(parseDkimKey('v=DKIM1; k=rsa').error ?? '', /p tag/);
});

test('describeKey reports rsa 2048, rsa 1024, ed25519 and unknown', () => {
  const k2048 = parseDkimKey(fixtureRecord('all-good', 'google._domainkey.example.com'));
  assert.deepEqual(describeKey(k2048.k, k2048.p ?? ''), { keyType: 'rsa', bits: 2048 });
  const k1024 = parseDkimKey(fixtureRecord('dkim-1024', 'selector1._domainkey.example.com'));
  assert.deepEqual(describeKey(k1024.k, k1024.p ?? ''), { keyType: 'rsa', bits: 1024 });
  const ed = parseDkimKey(fixtureRecord('dkim-ed25519', 'mail._domainkey.example.com'));
  assert.deepEqual(describeKey(ed.k, ed.p ?? ''), { keyType: 'ed25519', bits: 256 });
  assert.deepEqual(describeKey('rsa', 'bm90IGEga2V5'), { keyType: 'unknown', bits: null });
  assert.deepEqual(describeKey('ed25519', 'bm90IGEga2V5'), { keyType: 'unknown', bits: null });
  assert.deepEqual(describeKey('dsa', k2048.p ?? ''), { keyType: 'unknown', bits: null });
});

test('probeDkim finds the google 2048 key with no warnings', async () => {
  const result = await probeDkim('example.com', [], zoneResolver(loadZone('dkim-google-2048')));
  assert.deepEqual(result.selectors, [{ selector: 'google', keyType: 'rsa', bits: 2048, revoked: false, flags: [] }]);
  assert.equal(result.probed.length, DEFAULT_SELECTORS.length);
  assert.deepEqual(result.findings.map((f) => f.severity), ['info']);
  assert.match(result.findings[0]?.message ?? '', /google/);
  assert.match(result.findings[0]?.message ?? '', /2048/);
});

test('probeDkim warns on 1024-bit, revoked and unparseable keys', async () => {
  const weak = await probeDkim('example.com', [], zoneResolver(loadZone('dkim-1024')));
  assert.equal(weak.selectors[0]?.bits, 1024);
  assert.match(byId(weak.findings, 'dkim.rsa-weak')[0]?.message ?? '', /1024/);
  assert.equal(byId(weak.findings, 'dkim.rsa-weak')[0]?.severity, 'warning');

  const revoked = await probeDkim('example.com', [], zoneResolver(loadZone('dkim-revoked')));
  assert.equal(revoked.selectors[0]?.revoked, true);
  assert.match(byId(revoked.findings, 'dkim.revoked')[0]?.message ?? '', /revoked/);

  const bad = await probeDkim('example.com', [], zoneResolver(variant(loadZone('dkim-none'), { 'k2._domainkey.example.com': { TXT: ['v=DKIM1; k=rsa; p=bm90IGEga2V5'] } })));
  assert.equal(bad.selectors[0]?.keyType, 'unknown');
  assert.equal(byId(bad.findings, 'dkim.unparseable')[0]?.severity, 'warning');

  const ed = await probeDkim('example.com', [], zoneResolver(loadZone('dkim-ed25519')));
  assert.deepEqual(ed.selectors[0], { selector: 'mail', keyType: 'ed25519', bits: 256, revoked: false, flags: [] });
  assert.equal(byId(ed.findings, 'dkim.rsa-weak').length, 0);
});

test('probeDkim reports exactly one info pointing at --selector when nothing is found', async () => {
  const result = await probeDkim('example.com', [], zoneResolver(loadZone('dkim-none')));
  assert.deepEqual(result.selectors, []);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0]?.id, 'dkim.none');
  assert.equal(result.findings[0]?.severity, 'info');
  assert.match(result.findings[0]?.message ?? '', /--selector/);
});

test('probeDkim adds custom selectors, deduplicates, and caps concurrency at 5', async () => {
  const spy = spyResolver(zoneResolver(loadZone('dkim-google-2048')));
  const result = await probeDkim('example.com', ['custom1', 'Google', 'custom1'], spy.resolver);
  const names = spy.queries.map((q) => q.name);
  assert.equal(spy.queries.every((q) => q.type === 'TXT'), true);
  assert.equal(names.length, DEFAULT_SELECTORS.length + 1);
  assert.ok(names.includes('custom1._domainkey.example.com'));
  for (const selector of DEFAULT_SELECTORS) assert.ok(names.includes(`${selector}._domainkey.example.com`));
  assert.equal(new Set(names).size, names.length);
  assert.equal(result.probed.length, DEFAULT_SELECTORS.length + 1);
  assert.ok(spy.maxInFlight <= 5, `max in flight was ${spy.maxInFlight}`);
  assert.ok(spy.maxInFlight >= 2, 'expected the probe to run selectors concurrently');
});

test('probeDkim sorts results by selector regardless of resolution order', async () => {
  const zone = variant(loadZone('dkim-none'), {
    'zoho._domainkey.example.com': { TXT: ['v=DKIM1; k=rsa; p='] },
    'dkim._domainkey.example.com': { TXT: ['v=DKIM1; k=rsa; p='] },
    'k1._domainkey.example.com': { TXT: ['v=DKIM1; k=rsa; p='] },
  });
  const inner = zoneResolver(zone);
  let arrival = 0;
  const reversed: Resolver = {
    ...inner,
    resolveTxt: (name) => {
      const delay = 30 - (arrival++ % 30);
      return new Promise((resolve, reject) => {
        setTimeout(() => inner.resolveTxt(name).then(resolve, reject), delay);
      });
    },
  };
  const result = await probeDkim('example.com', [], reversed);
  assert.deepEqual(result.selectors.map((s) => s.selector), ['dkim', 'k1', 'zoho']);
});

test('probeDkim reports resolver errors per selector as info without crashing', async () => {
  const result = await probeDkim('example.com', ['s1'], throwingResolver('ETIMEOUT'));
  assert.equal(result.selectors.length, 0);
  const errors = byId(result.findings, 'dkim.lookup-error');
  assert.equal(errors.length, DEFAULT_SELECTORS.length);
  assert.match(errors[0]?.message ?? '', /ETIMEOUT/);
  assert.equal(byId(result.findings, 'dkim.none').length, 0);

  const partial: Resolver = {
    ...zoneResolver(loadZone('dkim-google-2048')),
    resolveTxt: (name) => (name.startsWith('k1.') ? Promise.reject(new DnsError('ESERVFAIL')) : zoneResolver(loadZone('dkim-google-2048')).resolveTxt(name)),
  };
  const mixed = await probeDkim('example.com', [], partial);
  assert.equal(mixed.selectors.length, 1);
  assert.equal(byId(mixed.findings, 'dkim.lookup-error').length, 1);
});
