import { test } from 'node:test';
import assert from 'node:assert/strict';
import { systemResolver, wrapDns } from '../src/resolver.ts';
import { DnsError } from '../src/types.ts';

function nodeError(code: string): Error & { code: string } {
  return Object.assign(new Error(`query failed ${code}`), { code });
}

const fakeDns = {
  resolveTxt: async (_name: string) => [['v=spf1 ', '-all'], ['other']],
  resolveMx: async (_name: string) => [{ priority: 0, exchange: '' }, { priority: 10, exchange: 'mx.example.com' }],
  resolve4: async (_name: string) => ['192.0.2.1'],
  resolve6: async (_name: string) => ['2001:db8::1'],
};

test('wrapDns joins TXT chunks per record and normalizes an empty MX exchange to "."', async () => {
  const resolver = wrapDns(fakeDns, 1000);
  assert.deepEqual(await resolver.resolveTxt('example.com'), ['v=spf1 -all', 'other']);
  assert.deepEqual(await resolver.resolveMx('example.com'), [
    { priority: 0, exchange: '.' },
    { priority: 10, exchange: 'mx.example.com' },
  ]);
  assert.deepEqual(await resolver.resolve4('example.com'), ['192.0.2.1']);
  assert.deepEqual(await resolver.resolve6('example.com'), ['2001:db8::1']);
});

test('wrapDns maps a query that never settles to DnsError ETIMEOUT within the timeout', async () => {
  const hang = () => new Promise<never>(() => {});
  const resolver = wrapDns({ resolveTxt: hang, resolveMx: hang, resolve4: hang, resolve6: hang }, 50);
  const started = Date.now();
  await assert.rejects(resolver.resolveTxt('example.com'), (err: unknown) => err instanceof DnsError && err.code === 'ETIMEOUT');
  assert.ok(Date.now() - started < 1000);
});

test('wrapDns re-throws node dns errors as DnsError with the same code', async () => {
  const failing = {
    resolveTxt: async (_name: string) => { throw nodeError('ENOTFOUND'); },
    resolveMx: async (_name: string) => { throw nodeError('ENODATA'); },
    resolve4: async (_name: string) => { throw nodeError('ESERVFAIL'); },
    resolve6: async (_name: string) => { throw new Error('plain failure'); },
  };
  const resolver = wrapDns(failing, 1000);
  await assert.rejects(resolver.resolveTxt('x'), (err: unknown) => err instanceof DnsError && err.code === 'ENOTFOUND');
  await assert.rejects(resolver.resolveMx('x'), (err: unknown) => err instanceof DnsError && err.code === 'ENODATA');
  await assert.rejects(resolver.resolve4('x'), (err: unknown) => err instanceof DnsError && err.code === 'ESERVFAIL');
  await assert.rejects(resolver.resolve6('x'), (err: unknown) => err instanceof DnsError && err.code === 'EUNKNOWN');
});

test('systemResolver builds a resolver object without issuing queries', () => {
  const resolver = systemResolver({ timeoutMs: 100, servers: ['192.0.2.53'] });
  for (const method of ['resolveTxt', 'resolveMx', 'resolve4', 'resolve6'] as const) {
    assert.equal(typeof resolver[method], 'function');
  }
});
