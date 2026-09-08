// Orchestrates the four domain checks into one DomainReport. Pure function of
// the resolver: identical answers produce identical reports.
import { auditDmarc } from './dmarc.ts';
import { probeDkim } from './dkim.ts';
import { auditExtras } from './extras.ts';
import { scoreFindings } from './grade.ts';
import { auditMx } from './mx.ts';
import { auditSpf } from './spf.ts';
import type { DomainReport, Finding, Resolver } from './types.ts';
import { DnsError, DomainNotFoundError, ResolverUnreachableError } from './types.ts';

export interface AuditOptions {
  selectors?: readonly string[];
}

type ApexType = 'TXT' | 'MX' | 'A' | 'AAAA';

export async function auditDomain(domain: string, resolver: Resolver, options: AuditOptions = {}): Promise<DomainReport> {
  const apex = domain.toLowerCase();
  const notFound: Record<ApexType, boolean> = { TXT: false, MX: false, A: false, AAAA: false };
  // A query is answered when it returns records or an authoritative ENOTFOUND or
  // ENODATA. Any other DnsError code is a transport failure; if no query at all
  // is answered, the resolver is unreachable and the audit cannot grade.
  let queries = 0;
  let answered = 0;
  const failureCodes = new Set<string>();
  const track = <T>(type: ApexType, name: string, run: () => Promise<T>): Promise<T> => {
    queries += 1;
    return run().then(
      (value) => {
        answered += 1;
        return value;
      },
      (err: unknown) => {
        if (err instanceof DnsError && (err.code === 'ENOTFOUND' || err.code === 'ENODATA')) {
          answered += 1;
          if (name.toLowerCase() === apex && err.code === 'ENOTFOUND') notFound[type] = true;
        } else if (err instanceof DnsError) {
          failureCodes.add(err.code);
        }
        throw err;
      },
    );
  };
  const tracked: Resolver = {
    resolveTxt: (name) => track('TXT', name, () => resolver.resolveTxt(name)),
    resolveMx: (name) => track('MX', name, () => resolver.resolveMx(name)),
    resolve4: (name) => track('A', name, () => resolver.resolve4(name)),
    resolve6: (name) => track('AAAA', name, () => resolver.resolve6(name)),
  };

  const [spf, dmarc, dkim, mx, extras] = await Promise.all([
    auditSpf(apex, tracked),
    auditDmarc(apex, tracked),
    probeDkim(apex, options.selectors ?? [], tracked),
    auditMx(apex, tracked),
    auditExtras(apex, tracked),
  ]);

  if (queries > 0 && answered === 0) {
    throw new ResolverUnreachableError(apex, [...failureCodes].sort(), queries);
  }
  if (notFound.TXT && notFound.MX && notFound.A && notFound.AAAA) {
    throw new DomainNotFoundError(apex);
  }

  const findings: Finding[] = [...spf.findings, ...dmarc.findings, ...dkim.findings, ...mx.findings, ...extras.findings];
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
      extras: { bimi: extras.bimi, mtaSts: extras.mtaSts, tlsRpt: extras.tlsRpt },
    },
    findings,
  };
}
