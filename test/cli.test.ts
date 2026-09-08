import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { repoRoot, runCli } from './helpers.ts';

test('A1: --help, domain --help and headers --help print usage to stdout and exit 0', async () => {
  for (const args of [['--help'], ['-h'], ['domain', '--help'], ['headers', '--help']]) {
    const result = await runCli(args);
    assert.equal(result.code, 0, `args ${args.join(' ')} stderr: ${result.stderr}`);
    assert.match(result.stdout, /Usage:/);
    assert.match(result.stdout, /mailguard/);
  }
});

test('A1: bare invocation, unknown command, missing argument and unknown flag exit 2 with usage on stderr', async () => {
  for (const args of [[], ['bogus'], ['domain'], ['domain', 'example.com', '--nope'], ['headers', '--nope']]) {
    const result = await runCli(args);
    assert.equal(result.code, 2, `args ${args.join(' ')}`);
    assert.match(result.stderr, /Usage:/);
    assert.equal(result.stdout, '');
  }
});

test('--version prints the package.json version', async () => {
  const pkg = JSON.parse(readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
  const result = await runCli(['--version']);
  assert.equal(result.code, 0);
  assert.equal(result.stdout, `mailguard ${pkg.version}\n`);
});

import { auditDomain } from '../src/audit.ts';
import { toJson } from '../src/report.ts';
import { zoneResolver } from '../src/zone.ts';
import { loadZone, withoutNodeWarnings } from './helpers.ts';

const zone = (name: string) => `test/fixtures/zones/${name}.json`;

test('A2: domain --zone all-good --json prints exactly the report JSON, exit 0, nothing on stderr', async () => {
  const result = await runCli(['domain', 'example.com', '--zone', zone('all-good'), '--json']);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(withoutNodeWarnings(result.stderr).trim(), '');
  const expected = toJson(await auditDomain('example.com', zoneResolver(loadZone('all-good'))));
  assert.equal(result.stdout, expected);
  assert.deepEqual(JSON.parse(result.stdout).grade, 'A');
});

test('A3/A6: nothing-configured exits 1 with grade F; text mode shows Grade', async () => {
  const json = await runCli(['domain', 'example.com', '--zone', zone('nothing-configured'), '--json']);
  assert.equal(json.code, 1);
  assert.equal(JSON.parse(json.stdout).grade, 'F');
  const text = await runCli(['domain', 'example.com', '--zone', zone('nothing-configured')]);
  assert.equal(text.code, 1);
  assert.match(text.stdout, /Grade: F \(score 30\)/);
  assert.match(text.stdout, /\[error\]/);
  const good = await runCli(['domain', 'Example.COM.', '--zone', zone('all-good')]);
  assert.equal(good.code, 0);
  assert.match(good.stdout, /^Domain: example\.com\n/);
  assert.match(good.stdout, /Grade: A \(score 100\)/);
});

test('A4: --selector reaches the DKIM probe through the CLI', async () => {
  const result = await runCli(['domain', 'example.com', '--zone', zone('all-good'), '--selector', 'custom1', '--selector', 'custom2', '--json']);
  assert.equal(result.code, 0);
  const report = JSON.parse(result.stdout);
  assert.ok(report.checks.dkim.probed.includes('custom1'));
  assert.ok(report.checks.dkim.probed.includes('custom2'));
});

test('A5: usage errors around --zone, --timeout and the domain argument exit 2', async () => {
  const cases: string[][] = [
    ['domain', 'example.com', '--zone', zone('all-good'), '--dns', '192.0.2.53'],
    ['domain', 'example.com', '--zone', zone('all-good'), '--timeout', '100'],
    ['domain', 'example.com', '--zone', 'test/fixtures/zones/does-not-exist.json'],
    ['domain', 'example.com', '--zone', 'package.json'],
    ['domain', 'not a domain', '--zone', zone('all-good')],
    ['domain', '-bad.example.com', '--zone', zone('all-good')],
    ['domain', 'example.com', 'extra', '--zone', zone('all-good')],
    ['domain', 'example.com', '--timeout', 'abc'],
    ['domain', 'example.com', '--timeout', '0'],
  ];
  for (const args of cases) {
    const result = await runCli(args);
    assert.equal(result.code, 2, `args ${args.join(' ')} stderr: ${result.stderr}`);
    assert.equal(result.stdout, '');
    assert.notEqual(withoutNodeWarnings(result.stderr).trim(), '');
  }
});

test('A7: nxdomain zone exits 2 with "does not resolve" on stderr', async () => {
  const result = await runCli(['domain', 'example.com', '--zone', zone('nxdomain')]);
  assert.equal(result.code, 2);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /does not resolve/);
});
