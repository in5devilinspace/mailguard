// DMARC (RFC 7489) record parser and auditor.
import type { DmarcSummary, Finding, Resolver, Severity } from './types.ts';
import { DnsError } from './types.ts';

export type DmarcPolicy = 'none' | 'quarantine' | 'reject';

export interface DmarcParseResult {
  tags: Record<string, string>;
  p: DmarcPolicy | null;
  sp: DmarcPolicy | null;
  pct: number;
  rua: string[];
  ruf: string[];
  adkim: 'r' | 's';
  aspf: 'r' | 's';
  fo: string | null;
  ri: string | null;
  rf: string | null;
  error: string | null;
}

export interface DmarcAudit extends DmarcSummary {
  findings: Finding[];
}

const POLICIES: ReadonlySet<string> = new Set(['none', 'quarantine', 'reject']);
const POLICY_RANK: Record<DmarcPolicy, number> = { none: 0, quarantine: 1, reject: 2 };

/**
 * Organizational domain by label stripping: keeps the last two labels. This is
 * wrong for public suffixes such as co.uk; no public suffix list is bundled.
 */
export function organizationalDomain(domain: string): string {
  const labels = domain.toLowerCase().split('.').filter((label) => label !== '');
  if (labels.length <= 2) return labels.join('.');
  return labels.slice(-2).join('.');
}

export function isDmarcRecord(txt: string): boolean {
  return /^\s*v\s*=\s*DMARC1\s*(;|$)/i.test(txt);
}

function splitList(value: string): string[] {
  return value.split(',').map((item) => item.trim()).filter((item) => item !== '');
}

export function parseDmarc(record: string): DmarcParseResult {
  const result: DmarcParseResult = {
    tags: {},
    p: null,
    sp: null,
    pct: 100,
    rua: [],
    ruf: [],
    adkim: 'r',
    aspf: 'r',
    fo: null,
    ri: null,
    rf: null,
    error: null,
  };
  const fail = (error: string): DmarcParseResult => ({ ...result, error });
  const parts = record.split(';').map((part) => part.trim()).filter((part) => part !== '');
  const pairs: [string, string][] = [];
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq === -1) return fail(`tag "${part}" has no value`);
    pairs.push([part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim()]);
  }
  const first = pairs[0];
  if (first === undefined || first[0] !== 'v' || first[1].toUpperCase() !== 'DMARC1') {
    return fail('v=DMARC1 must be the first tag');
  }
  for (const [name, value] of pairs) result.tags[name] = value;
  const p = result.tags['p'];
  if (p === undefined) return fail('record has no p tag (policy is required)');
  if (!POLICIES.has(p.toLowerCase())) return fail(`p=${p} is not one of none, quarantine or reject`);
  result.p = p.toLowerCase() as DmarcPolicy;
  const sp = result.tags['sp'];
  if (sp !== undefined) {
    if (!POLICIES.has(sp.toLowerCase())) return fail(`sp=${sp} is not one of none, quarantine or reject`);
    result.sp = sp.toLowerCase() as DmarcPolicy;
  }
  const pct = result.tags['pct'];
  if (pct !== undefined) {
    if (!/^\d{1,3}$/.test(pct) || Number(pct) > 100) return fail(`pct=${pct} must be an integer from 0 to 100`);
    result.pct = Number(pct);
  }
  result.rua = splitList(result.tags['rua'] ?? '');
  result.ruf = splitList(result.tags['ruf'] ?? '');
  for (const key of ['adkim', 'aspf'] as const) {
    const value = result.tags[key];
    if (value !== undefined) {
      const mode = value.toLowerCase();
      if (mode !== 'r' && mode !== 's') return fail(`${key}=${value} must be r or s`);
      result[key] = mode;
    }
  }
  result.fo = result.tags['fo'] ?? null;
  result.ri = result.tags['ri'] ?? null;
  result.rf = result.tags['rf'] ?? null;
  return result;
}

type FetchResult = { records: string[] } | { errorCode: string };

async function fetchDmarc(resolver: Resolver, name: string): Promise<FetchResult> {
  try {
    return { records: (await resolver.resolveTxt(name)).filter(isDmarcRecord) };
  } catch (err) {
    if (err instanceof DnsError) {
      if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') return { records: [] };
      return { errorCode: err.code };
    }
    throw err;
  }
}

export async function auditDmarc(domain: string, resolver: Resolver): Promise<DmarcAudit> {
  const findings: Finding[] = [];
  const add = (id: string, severity: Severity, message: string): void => {
    findings.push({ check: 'dmarc', id, severity, message });
  };
  const summary: DmarcAudit = {
    record: null,
    source: null,
    inherited: false,
    policy: null,
    subdomainPolicy: null,
    effectivePolicy: null,
    pct: null,
    rua: [],
    findings,
  };

  const own = `_dmarc.${domain}`;
  let fetched = await fetchDmarc(resolver, own);
  if ('errorCode' in fetched) {
    add('dmarc.lookup-error', 'warning', `TXT lookup for ${own} failed with ${fetched.errorCode}, so DMARC could not be checked`);
    return summary;
  }
  let source = domain;
  const org = organizationalDomain(domain);
  if (fetched.records.length === 0 && org !== domain.toLowerCase()) {
    const parent = await fetchDmarc(resolver, `_dmarc.${org}`);
    if ('errorCode' in parent) {
      add('dmarc.lookup-error', 'warning', `TXT lookup for _dmarc.${org} failed with ${parent.errorCode}, so the inherited DMARC policy could not be checked`);
      return summary;
    }
    if (parent.records.length > 0) {
      fetched = parent;
      source = org;
      summary.inherited = true;
    }
  }
  summary.source = source;
  if (fetched.records.length === 0) {
    add('dmarc.missing', 'error', `${domain} has no DMARC record at _dmarc.${domain}${org !== domain.toLowerCase() ? ` or _dmarc.${org}` : ''}`);
    return summary;
  }
  if (fetched.records.length > 1) {
    add('dmarc.multiple', 'error', `_dmarc.${source} publishes multiple DMARC records (${fetched.records.length}), which receivers treat as no policy`);
    return summary;
  }
  const record = fetched.records[0] ?? '';
  summary.record = record;
  const parsed = parseDmarc(record);
  if (parsed.error !== null || parsed.p === null) {
    add('dmarc.invalid', 'error', `DMARC record at _dmarc.${source} is invalid: ${parsed.error ?? 'record has no p tag'}`);
    return summary;
  }
  summary.policy = parsed.p;
  summary.subdomainPolicy = parsed.sp;
  summary.pct = parsed.pct;
  summary.rua = parsed.rua;
  const effective: DmarcPolicy = summary.inherited ? (parsed.sp ?? parsed.p) : parsed.p;
  summary.effectivePolicy = effective;
  if (summary.inherited) {
    add('dmarc.inherited', 'info', `No DMARC record at _dmarc.${domain}; the record at _dmarc.${source} applies with effective policy ${effective}${parsed.sp !== null ? ' (from sp)' : ' (from p)'}`);
  }
  if (effective === 'none') {
    add('dmarc.p-none', 'warning', `DMARC policy for ${domain} is p=none, so failing mail is only reported, never quarantined or rejected`);
  }
  if (parsed.pct < 100) {
    add('dmarc.pct', 'warning', `DMARC pct=${parsed.pct} applies the policy to only ${parsed.pct}% of failing mail`);
  }
  if (parsed.rua.length === 0) {
    add('dmarc.no-rua', 'warning', `DMARC record at _dmarc.${source} has no rua tag, so no aggregate reports are collected`);
  }
  if (parsed.sp !== null && POLICY_RANK[parsed.sp] < POLICY_RANK[parsed.p]) {
    add('dmarc.sp-weaker', 'warning', `DMARC subdomain policy sp=${parsed.sp} is weaker than p=${parsed.p} at _dmarc.${source}`);
  }
  add('dmarc.record', 'info', `DMARC record at _dmarc.${source} is "${record}"`);
  return summary;
}
