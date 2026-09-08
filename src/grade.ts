// Scoring rubric. DEDUCTIONS is the single source of truth; the README table
// mirrors it and test/grade.test.ts pins every number.
import type { Finding, Grade } from './types.ts';

export const DEDUCTIONS: Readonly<Record<string, number>> = Object.freeze({
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
});

/** Minimum score for each band; anything below D is F. */
export const BANDS: Readonly<{ A: number; B: number; C: number; D: number }> = Object.freeze({ A: 90, B: 80, C: 65, D: 50 });

export interface Score {
  score: number;
  grade: Grade;
  applied: { id: string; points: number }[];
}

export function gradeFor(score: number): Grade {
  if (score >= BANDS.A) return 'A';
  if (score >= BANDS.B) return 'B';
  if (score >= BANDS.C) return 'C';
  if (score >= BANDS.D) return 'D';
  return 'F';
}

/** 100 minus each distinct deduction id present, applied once per id, floored at 0. */
export function scoreFindings(findings: readonly Finding[]): Score {
  const applied: { id: string; points: number }[] = [];
  const seen = new Set<string>();
  let score = 100;
  for (const finding of findings) {
    const points = DEDUCTIONS[finding.id];
    if (points === undefined || seen.has(finding.id)) continue;
    seen.add(finding.id);
    applied.push({ id: finding.id, points });
    score -= points;
  }
  score = Math.max(0, score);
  return { score, grade: gradeFor(score), applied };
}

export function exitCodeForGrade(grade: Grade): 0 | 1 {
  return grade === 'A' || grade === 'B' ? 0 : 1;
}
