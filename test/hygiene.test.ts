import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { repoRoot } from './helpers.ts';

function walk(dir: string, skip: Set<string>): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (skip.has(entry)) continue;
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full, skip));
    else out.push(full);
  }
  return out;
}

const SKIP = new Set(['.git', 'node_modules', 'package-lock.json']);
const codeFiles = walk(path.join(repoRoot, 'src'), SKIP)
  .concat(walk(path.join(repoRoot, 'bin'), SKIP))
  .concat(walk(path.join(repoRoot, 'test'), SKIP));

test('node:dns is imported only by src/resolver.ts', () => {
  const offenders = codeFiles.filter((file) => {
    if (file === path.join(repoRoot, 'src', 'resolver.ts')) return false;
    if (file === path.join(repoRoot, 'test', 'hygiene.test.ts')) return false;
    return readFileSync(file, 'utf8').includes('node:dns');
  });
  assert.deepEqual(offenders, []);
});

// Leftover-work wording that must never ship in src, bin or the README.
const WORK_MARKERS = /\b(TODO|FIXME|placeholder|not implemented|unimplemented)\b/i;

test('the work-marker pattern catches TODO, FIXME, placeholder and not-implemented wording', () => {
  const flagged = ['// TODO: wire this up', 'FIXME later', 'return placeholder;', 'throw new Error("Not implemented")', 'unimplemented branch'];
  for (const sample of flagged) assert.ok(WORK_MARKERS.test(sample), `should flag ${JSON.stringify(sample)}`);
  const clean = ['SPF lookup count', 'DKIM selector default', 'the audit is implemented in audit.ts', 'todos.example.com'];
  for (const sample of clean) assert.ok(!WORK_MARKERS.test(sample), `should not flag ${JSON.stringify(sample)}`);
});

test('no TODO, FIXME or placeholder markers in src, bin or README', () => {
  const files = walk(path.join(repoRoot, 'src'), SKIP)
    .concat(walk(path.join(repoRoot, 'bin'), SKIP))
    .concat([path.join(repoRoot, 'README.md')]);
  const offenders = files.filter((file) => WORK_MARKERS.test(readFileSync(file, 'utf8')));
  assert.deepEqual(offenders, []);
});

test('no em-dash in README or src', () => {
  const files = walk(path.join(repoRoot, 'src'), SKIP).concat([path.join(repoRoot, 'README.md')]);
  const offenders = files.filter((file) => readFileSync(file, 'utf8').includes('—'));
  assert.deepEqual(offenders, []);
});

const PHONE = /\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}/;
const EMAIL = /[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g;
const SECRETS = [
  /AKIA[0-9A-Z]{16}/,
  /ghp_[A-Za-z0-9]{36}/,
  /xox[baprs]-/,
  /sk-[A-Za-z0-9]{20,}/,
  /AIza[0-9A-Za-z_-]{35}/,
  /-----BEGIN .*PRIVATE KEY-----/,
];

function emailDomainAllowed(domain: string): boolean {
  const d = domain.toLowerCase();
  const bases = ['example.com', 'example.net', 'example.org', 'bulk-mailer.net'];
  if (bases.some((base) => d === base || d.endsWith('.' + base))) return true;
  return d.endsWith('.test') || d.endsWith('.invalid');
}

test('repo contains no phone numbers, real email addresses or secret-shaped strings', () => {
  const problems: string[] = [];
  const self = path.join(repoRoot, 'test', 'hygiene.test.ts');
  for (const file of walk(repoRoot, SKIP)) {
    if (file === self) continue;
    const text = readFileSync(file, 'utf8');
    const rel = path.relative(repoRoot, file);
    if (PHONE.test(text)) problems.push(`${rel}: phone number pattern`);
    for (const match of text.matchAll(EMAIL)) {
      const domain = match[1] ?? '';
      if (!emailDomainAllowed(domain)) problems.push(`${rel}: email ${match[0]}`);
    }
    for (const pattern of SECRETS) {
      if (pattern.test(text)) problems.push(`${rel}: secret pattern ${pattern}`);
    }
  }
  assert.deepEqual(problems, []);
});

test('package.json keeps zero runtime dependencies and the expected metadata', () => {
  const pkg = JSON.parse(readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
  assert.equal('dependencies' in pkg, false);
  assert.deepEqual(Object.keys(pkg.devDependencies).sort(), ['@types/node', 'typescript']);
  assert.equal(pkg.engines.node, '>=24');
  assert.equal(pkg.private, true);
  assert.equal(pkg.license, 'MIT');
  assert.equal(pkg.author, 'Matt Dundore');
});

test('LICENSE is MIT in the name of Matt Dundore', () => {
  const text = readFileSync(path.join(repoRoot, 'LICENSE'), 'utf8');
  assert.match(text, /MIT/);
  assert.match(text, /Matt Dundore/);
});

test('README sections appear in the documented order', () => {
  const readme = readFileSync(path.join(repoRoot, 'README.md'), 'utf8');
  const headings = [
    '# mailguard',
    '## Quickstart',
    '## Commands and flags',
    '## Example output',
    '## Grading',
    '## Exit codes',
    '## JSON output',
    '## Default DKIM selectors',
    '## Organizational domain limitation',
    '## What it does not do',
  ];
  let last = -1;
  for (const heading of headings) {
    const index = readme.indexOf(heading + '\n');
    assert.ok(index > last, `heading "${heading}" missing or out of order`);
    last = index;
  }
});
