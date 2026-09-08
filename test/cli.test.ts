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
