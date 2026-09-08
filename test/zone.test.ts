import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { loadZoneFile, zoneResolver } from '../src/zone.ts';
import { DnsError, ZoneFormatError } from '../src/types.ts';
import { loadZone, repoRoot } from './helpers.ts';

const scratch = process.env['TMPDIR'] ?? '/tmp';
function tmpZone(name: string, content: string): string {
  const file = path.join(scratch, `mailguard-zone-${process.pid}-${name}.json`);
  writeFileSync(file, content);
  return file;
}

test('loadZoneFile reads a fixture and rejects malformed files with ZoneFormatError', () => {
  const zone = loadZoneFile(path.join(repoRoot, 'test', 'fixtures', 'zones', 'all-good.json'));
  assert.ok(zone['example.com']);
  assert.throws(() => loadZoneFile(tmpZone('array', '[1, 2]')), ZoneFormatError);
  assert.throws(() => loadZoneFile(tmpZone('txt', '{"example.com": {"TXT": "v=spf1 -all"}}')), (err: unknown) => {
    return err instanceof ZoneFormatError && /TXT/.test(err.message) && /example\.com/.test(err.message);
  });
  assert.throws(() => loadZoneFile(tmpZone('mx', '{"example.com": {"MX": [{"exchange": "mx.example.com"}]}}')), (err: unknown) => {
    return err instanceof ZoneFormatError && /priority/.test(err.message);
  });
  assert.throws(() => loadZoneFile(tmpZone('json', '{not json')), ZoneFormatError);
  assert.throws(() => loadZoneFile(path.join(scratch, 'mailguard-does-not-exist.json')), ZoneFormatError);
});

test('zoneResolver throws ENOTFOUND for absent names and ENODATA for present names lacking the type', async () => {
  const resolver = zoneResolver(loadZone('all-good'));
  await assert.rejects(resolver.resolveTxt('missing.example.com'), (err: unknown) => err instanceof DnsError && err.code === 'ENOTFOUND');
  await assert.rejects(resolver.resolveMx('_spf.example.com'), (err: unknown) => err instanceof DnsError && err.code === 'ENODATA');
  await assert.rejects(resolver.resolve4('_spf.example.com'), (err: unknown) => err instanceof DnsError && err.code === 'ENODATA');
  await assert.rejects(resolver.resolve6('mx2.example.com'), (err: unknown) => err instanceof DnsError && err.code === 'ENODATA');
});

test('zoneResolver lookups are case-insensitive and ignore a trailing dot', async () => {
  const resolver = zoneResolver(loadZone('all-good'));
  assert.deepEqual(await resolver.resolve4('EXAMPLE.COM.'), ['192.0.2.1']);
  assert.deepEqual(await resolver.resolveMx('Example.Com'), [
    { priority: 20, exchange: 'mx2.example.com' },
    { priority: 10, exchange: 'mx1.example.com' },
  ]);
});

test('zoneResolver concatenates TXT chunks into one record and returns copies', async () => {
  const zone = loadZone('all-good');
  const resolver = zoneResolver(zone);
  const dkim = await resolver.resolveTxt('google._domainkey.example.com');
  assert.equal(dkim.length, 1);
  assert.match(dkim[0] ?? '', /^v=DKIM1; k=rsa; p=MIIBIjAN/);
  assert.ok((dkim[0] ?? '').length > 255);
  const a1 = await resolver.resolve4('example.com');
  a1.push('203.0.113.9');
  const a2 = await resolver.resolve4('example.com');
  assert.deepEqual(a2, ['192.0.2.1']);
  const mx = await resolver.resolveMx('example.com');
  (mx[0] as { exchange: string }).exchange = 'changed';
  assert.equal((await resolver.resolveMx('example.com'))[0]?.exchange, 'mx2.example.com');
});
