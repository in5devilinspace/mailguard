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

import { main } from '../src/cli.ts';
import type { ResolverOptions } from '../src/cli.ts';
import { memoryIo, throwingResolver } from './helpers.ts';

test('A10: a resolver that answers nothing exits 2 with a message on stderr and nothing on stdout', async () => {
  for (const extra of [[], ['--json']]) {
    const io = memoryIo({ makeResolver: () => throwingResolver('ECONNREFUSED') });
    const code = await main(['domain', 'example.com', '--timeout', '300', ...extra], io.io);
    assert.equal(code, 2, `args ${extra.join(' ')} stderr: ${io.stderr()}`);
    assert.equal(io.stdout(), '');
    assert.match(io.stderr(), /^mailguard: example\.com could not be audited/);
    assert.match(io.stderr(), /ECONNREFUSED/);
    assert.doesNotMatch(io.stderr(), /Grade/);
  }
});

test('A11: --dns accepts IPv4 and IPv6 literals and rejects anything else with a usage error', async () => {
  // In-process: an invalid address must be rejected before any resolver is built.
  for (const bad of ['notanip', '', '999.1.1.1', '1.1.1.1:53', '[2001:db8::53]', ' 192.0.2.53']) {
    const io = memoryIo({ makeResolver: () => assert.fail(`resolver was built for --dns ${JSON.stringify(bad)}`) });
    const code = await main(['domain', 'example.com', '--dns', bad], io.io);
    assert.equal(code, 2, `--dns ${JSON.stringify(bad)} stderr: ${io.stderr()}`);
    assert.equal(io.stdout(), '');
    assert.match(io.stderr(), /^mailguard: --dns .*IPv4 or IPv6/);
    assert.match(io.stderr(), /Usage: mailguard domain/);
  }
  // Child process: the reviewer's exact commands must not leak a stack trace.
  for (const bad of ['notanip', '']) {
    const result = await runCli(['domain', 'example.com', '--dns', bad]);
    assert.equal(result.code, 2, `--dns ${JSON.stringify(bad)} stderr: ${result.stderr}`);
    assert.equal(result.stdout, '');
    assert.doesNotMatch(result.stderr, /ERR_INVALID_IP_ADDRESS|\n    at /);
  }
  // Valid literals reach the resolver factory untouched, together with --timeout.
  let seen: ResolverOptions | null = null;
  const io = memoryIo({
    makeResolver: (options) => {
      seen = options;
      return zoneResolver(loadZone('all-good'));
    },
  });
  const code = await main(['domain', 'example.com', '--dns', '192.0.2.53', '--dns', '2001:db8::53', '--timeout', '250'], io.io);
  assert.equal(code, 0, io.stderr());
  assert.deepEqual(seen, { timeoutMs: 250, servers: ['192.0.2.53', '2001:db8::53'] });
});

import { analyzeHeaders } from '../src/headers.ts';
import { readEml } from './helpers.ts';

test('A8: headers <file> --json prints the analysis JSON; text mode lists hops', async () => {
  const result = await runCli(['headers', 'test/fixtures/eml/gmail-pass.eml', '--json']);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(withoutNodeWarnings(result.stderr).trim(), '');
  const report = JSON.parse(result.stdout);
  for (const key of ['from', 'returnPath', 'hops', 'totalTransitSeconds', 'authResults', 'verdict', 'alignment', 'dkimSignatures', 'findings']) {
    assert.ok(key in report, `missing ${key}`);
  }
  assert.equal(result.stdout, toJson(analyzeHeaders(readEml('gmail-pass.eml'))));
  const text = await runCli(['headers', 'test/fixtures/eml/misaligned-dkim.eml']);
  assert.equal(text.code, 0);
  assert.match(text.stdout, /From: /);
  assert.match(text.stdout, /Hops/);
  assert.match(text.stdout, /Alignment: misaligned/);
  assert.match(text.stdout, /\[warning\]/);
});

test('A9: headers reads stdin (no argument or "-") and exits 2 on empty input or a missing file', async () => {
  const stdin = await runCli(['headers'], { stdin: readEml('headers-only.txt') });
  assert.equal(stdin.code, 0, stdin.stderr);
  assert.match(stdin.stdout, /Total transit: 2 s/);
  const dash = await runCli(['headers', '-', '--json'], { stdin: readEml('headers-only.txt') });
  assert.equal(dash.code, 0);
  assert.equal(JSON.parse(dash.stdout).hops.length, 2);
  const empty = await runCli(['headers'], { stdin: '' });
  assert.equal(empty.code, 2);
  assert.equal(empty.stdout, '');
  assert.match(empty.stderr, /no headers/);
  const missing = await runCli(['headers', 'test/fixtures/eml/does-not-exist.eml']);
  assert.equal(missing.code, 2);
  assert.match(missing.stderr, /does-not-exist\.eml/);
});
