// Orchestrates the four domain checks into one DomainReport. Pure function of
// the resolver: identical answers produce identical reports.
import { auditDmarc } from './dmarc.ts';
import { probeDkim } from './dkim.ts';
import { scoreFindings } from './grade.ts';
import { auditMx } from './mx.ts';
import { auditSpf } from './spf.ts';
import type { DomainReport, Finding, Resolver } from './types.ts';
import { DnsError, DomainNotFoundError } from './types.ts';

export interface AuditOptions {
  selectors?: readonly string[];
}

type ApexType = 'TXT' | 'MX' | 'A' | 'AAAA';

export async function auditDomain(domain: string, resolver: Resolver, options: AuditOptions = {}): Promise<DomainReport> {
  const apex = domain.toLowerCase();
  const notFound: Record<ApexType, boolean> = { TXT: false, MX: false, A: false, AAAA: false };
  const track = <T>(type: ApexType, name: string, run: () => Promise<T>): Promise<T> =>
    run().catch((err: unknown) => {
      if (name.toLowerCase() === apex && err instanceof DnsError && err.code === 'ENOTFOUND') notFound[type] = true;
      throw err;
    });
  const tracked: Resolver = {
    resolveTxt: (name) => track('TXT', name, () => resolver.resolveTxt(name)),
    resolveMx: (name) => track('MX', name, () => resolver.resolveMx(name)),
    resolve4: (name) => track('A', name, () => resolver.resolve4(name)),
    resolve6: (name) => track('AAAA', name, () => resolver.resolve6(name)),
  };

  const [spf, dmarc, dkim, mx] = await Promise.all([
    auditSpf(apex, tracked),
    auditDmarc(apex, tracked),
    probeDkim(apex, options.selectors ?? [], tracked),
    auditMx(apex, tracked),
  ]);

  if (notFound.TXT && notFound.MX && notFound.A && notFound.AAAA) {
    throw new DomainNotFoundError(apex);
  }

  const findings: Finding[] = [...spf.findings, ...dmarc.findings, ...dkim.findings, ...mx.findings];
  const { score, grade } = scoreFindings(findings);
  return {
    domain: apex,
    grade,
    score,
    checks: {
      spf: {
        record: spf.record,
        records: spf.records,
        lookupCount: spf.lookupCount,
        allQualifier: spf.allQualifier,
        includes: spf.includes,
        redirects: spf.redirects,
      },
      dmarc: {
        record: dmarc.record,
        source: dmarc.source,
        inherited: dmarc.inherited,
        policy: dmarc.policy,
        subdomainPolicy: dmarc.subdomainPolicy,
        effectivePolicy: dmarc.effectivePolicy,
        pct: dmarc.pct,
        rua: dmarc.rua,
      },
      dkim: { probed: dkim.probed, selectors: dkim.selectors },
      mx: { nullMx: mx.nullMx, records: mx.records },
    },
    findings,
  };
}
