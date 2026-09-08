import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { BANDS, DEDUCTIONS, exitCodeForGrade, gradeFor, scoreFindings } from '../src/grade.ts';
import type { Finding } from '../src/types.ts';
import { repoRoot } from './helpers.ts';

const EXPECTED: Record<string, number> = {
  'spf.plus-all': 40,
  'spf.missing': 30,
  'spf.multiple': 30,
  'spf.syntax': 30,
  'spf.loop': 30,
  'spf.question-all': 20,
  'spf.lookups-over-10': 25,
  'spf.lookups-8-to-10': 5,
  'spf.include-missing': 10,
  'spf.no-all': 5,
  'spf.ptr': 5,
  'dmarc.missing': 30,
  'dmarc.multiple': 30,
  'dmarc.invalid': 30,
  'dmarc.p-none': 25,
  'dmarc.pct': 5,
  'dmarc.no-rua': 5,
  'dmarc.sp-weaker': 5,
  'dkim.rsa-weak': 10,
  'mx.missing-a-present': 10,
  'mx.missing-no-a': 15,
  'mx.host-unresolvable': 15,
  'mx.ip-literal': 10,
};

const finding = (id: string): Finding => ({ check: 'spf', id, severity: 'error', message: `finding ${id}` });

test('DEDUCTIONS pins every rubric entry and nothing else', () => {
  assert.deepEqual(DEDUCTIONS, EXPECTED);
});

test('scoreFindings applies each deduction id once, ignores zero-point ids, floors at 0', () => {
  assert.deepEqual(scoreFindings([]), { score: 100, grade: 'A', applied: [] });
  const twice = scoreFindings([finding('dkim.rsa-weak'), finding('dkim.rsa-weak'), finding('dkim.found'), finding('spf.record')]);
  assert.equal(twice.score, 90);
  assert.equal(twice.grade, 'A');
  assert.deepEqual(twice.applied, [{ id: 'dkim.rsa-weak', points: 10 }]);
  const everything = scoreFindings(Object.keys(EXPECTED).map(finding));
  assert.equal(everything.score, 0);
  assert.equal(everything.grade, 'F');
  const pNone = scoreFindings([finding('dmarc.p-none')]);
  assert.deepEqual([pNone.score, pNone.grade], [75, 'C']);
  const nothing = scoreFindings([finding('spf.missing'), finding('dmarc.missing'), finding('mx.missing-a-present')]);
  assert.deepEqual([nothing.score, nothing.grade], [30, 'F']);
});

test('gradeFor band boundaries and exit codes', () => {
  assert.deepEqual(BANDS, { A: 90, B: 80, C: 65, D: 50 });
  const cases: [number, string][] = [[100, 'A'], [90, 'A'], [89, 'B'], [80, 'B'], [79, 'C'], [65, 'C'], [64, 'D'], [50, 'D'], [49, 'F'], [0, 'F']];
  for (const [score, grade] of cases) assert.equal(gradeFor(score), grade, `score ${score}`);
  assert.equal(exitCodeForGrade('A'), 0);
  assert.equal(exitCodeForGrade('B'), 0);
  assert.equal(exitCodeForGrade('C'), 1);
  assert.equal(exitCodeForGrade('D'), 1);
  assert.equal(exitCodeForGrade('F'), 1);
});

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

test('README grading table mirrors DEDUCTIONS id for id and point for point', () => {
  const readme = readFileSync(path.join(repoRoot, 'README.md'), 'utf8');
  for (const [id, points] of Object.entries(DEDUCTIONS)) {
    const row = new RegExp(`^\\|\\s*\`${escapeRegExp(id)}\`\\s*\\|\\s*-${points}\\s*\\|`, 'm');
    assert.match(readme, row, `README lacks a row for ${id} with -${points}`);
  }
});
