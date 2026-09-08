// BIMI, MTA-STS and TLS-RPT presence checks. Informational only: none of
// these findings carries a deduction. DNS only; the MTA-STS policy file, the
// BIMI logo and the certificate it points at are never fetched.
import type { ExtrasSummary, Finding, Resolver } from './types.ts';
import { DnsError } from './types.ts';

export interface ExtrasAudit extends ExtrasSummary {
  findings: Finding[];
}

export interface BimiParseResult {
  location: string | null;
  authority: string | null;
  error: string | null;
}

export interface MtaStsParseResult {
  id: string | null;
  error: string | null;
}

export interface TlsRptParseResult {
  rua: string[];
  error: string | null;
}

export function isBimiRecord(txt: string): boolean {
  return /^\s*v\s*=\s*BIMI1\s*(;|$)/i.test(txt);
}

export function isMtaStsRecord(txt: string): boolean {
  return /^\s*v\s*=\s*STSv1\s*(;|$)/i.test(txt);
}

export function isTlsRptRecord(txt: string): boolean {
  return /^\s*v\s*=\s*TLSRPTv1\s*(;|$)/i.test(txt);
}

type TagList = { tags: Record<string, string> } | { error: string };

/** Splits "a=1; b=2" into lowercase tags, requiring the given version tag first. */
function readTags(record: string, versionTag: string): TagList {
  const parts = record.split(';').map((part) => part.trim()).filter((part) => part !== '');
  const pairs: [string, string][] = [];
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq === -1) return { error: `tag "${part}" has no value` };
    pairs.push([part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim()]);
  }
  const first = pairs[0];
  if (first === undefined || first[0] !== 'v' || first[1].toLowerCase() !== versionTag.toLowerCase()) {
    return { error: `v=${versionTag} must be the first tag` };
  }
  const tags: Record<string, string> = {};
  for (const [name, value] of pairs) tags[name] = value;
  return { tags };
}

export function parseBimi(record: string): BimiParseResult {
  const read = readTags(record, 'BIMI1');
  if ('error' in read) return { location: null, authority: null, error: read.error };
  const location = read.tags['l'];
  if (location === undefined) return { location: null, authority: null, error: 'record has no l tag' };
  return { location, authority: read.tags['a'] ?? null, error: null };
}

export function parseMtaSts(record: string): MtaStsParseResult {
  const read = readTags(record, 'STSv1');
  if ('error' in read) return { id: null, error: read.error };
  const id = read.tags['id'];
  if (id === undefined || id === '') return { id: null, error: 'record has no id tag' };
  return { id, error: null };
}

export function parseTlsRpt(record: string): TlsRptParseResult {
  const read = readTags(record, 'TLSRPTv1');
  if ('error' in read) return { rua: [], error: read.error };
  const rua = (read.tags['rua'] ?? '').split(',').map((item) => item.trim()).filter((item) => item !== '');
  if (rua.length === 0) return { rua: [], error: 'record has no rua tag' };
  return { rua, error: null };
}

type FetchResult = { records: string[] } | { errorCode: string };

async function fetchRecords(resolver: Resolver, name: string, matches: (txt: string) => boolean): Promise<FetchResult> {
  try {
    return { records: (await resolver.resolveTxt(name)).filter(matches) };
  } catch (err) {
    if (err instanceof DnsError) {
      if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') return { records: [] };
      return { errorCode: err.code };
    }
    throw err;
  }
}

interface Protocol {
  key: 'bimi' | 'mta-sts' | 'tls-rpt';
  label: string;
  name: string;
  absent: string;
}

/**
 * Resolves the one record for a protocol, or emits the lookup-error, none or
 * multiple finding and returns null. Every finding here is info.
 */
function selectRecord(fetched: FetchResult, protocol: Protocol, findings: Finding[]): string | null {
  const add = (id: string, message: string): void => {
    findings.push({ check: 'extras', id: `extras.${protocol.key}-${id}`, severity: 'info', message });
  };
  if ('errorCode' in fetched) {
    findings.push({
      check: 'extras',
      id: 'extras.lookup-error',
      severity: 'info',
      message: `TXT lookup for ${protocol.name} failed with ${fetched.errorCode}, so ${protocol.label} could not be checked`,
    });
    return null;
  }
  if (fetched.records.length === 0) {
    add('none', protocol.absent);
    return null;
  }
  if (fetched.records.length > 1) {
    add('multiple', `${protocol.name} publishes multiple ${protocol.label} records (${fetched.records.length}), so receivers ignore ${protocol.label} for this domain`);
    return null;
  }
  return fetched.records[0] ?? null;
}

export async function auditExtras(domain: string, resolver: Resolver): Promise<ExtrasAudit> {
  const findings: Finding[] = [];
  const info = (id: string, message: string): void => {
    findings.push({ check: 'extras', id, severity: 'info', message });
  };
  const bimiName = `default._bimi.${domain}`;
  const stsName = `_mta-sts.${domain}`;
  const tlsName = `_smtp._tls.${domain}`;
  const [bimiFetched, stsFetched, tlsFetched] = await Promise.all([
    fetchRecords(resolver, bimiName, isBimiRecord),
    fetchRecords(resolver, stsName, isMtaStsRecord),
    fetchRecords(resolver, tlsName, isTlsRptRecord),
  ]);

  const result: ExtrasAudit = {
    bimi: { record: null, location: null, authority: null },
    mtaSts: { record: null, id: null },
    tlsRpt: { record: null, rua: [] },
    findings,
  };

  const bimiRecord = selectRecord(bimiFetched, {
    key: 'bimi',
    label: 'BIMI',
    name: bimiName,
    absent: `No BIMI record at ${bimiName}; BIMI is optional and only shows a brand logo in mail clients that support it`,
  }, findings);
  if (bimiRecord !== null) {
    result.bimi.record = bimiRecord;
    const parsed = parseBimi(bimiRecord);
    if (parsed.error !== null) {
      info('extras.bimi-invalid', `BIMI record at ${bimiName} is invalid: ${parsed.error}`);
    } else {
      result.bimi.location = parsed.location;
      result.bimi.authority = parsed.authority;
      if (parsed.location === '') {
        info('extras.bimi-found', `BIMI record at ${bimiName} declines to publish a logo (empty l tag)`);
      } else {
        const authority = parsed.authority !== null && parsed.authority !== ''
          ? ` with certificate ${parsed.authority}`
          : ' without a certificate (no a tag), which most mail clients require before showing the logo';
        info('extras.bimi-found', `BIMI record at ${bimiName} points to logo ${parsed.location}${authority}`);
      }
    }
  }

  const stsRecord = selectRecord(stsFetched, {
    key: 'mta-sts',
    label: 'MTA-STS',
    name: stsName,
    absent: `No MTA-STS record at ${stsName}; MTA-STS is optional and lets ${domain} require TLS from servers that deliver to it`,
  }, findings);
  if (stsRecord !== null) {
    result.mtaSts.record = stsRecord;
    const parsed = parseMtaSts(stsRecord);
    if (parsed.error !== null) {
      info('extras.mta-sts-invalid', `MTA-STS record at ${stsName} is invalid: ${parsed.error}`);
    } else {
      result.mtaSts.id = parsed.id;
      info('extras.mta-sts-found', `MTA-STS record at ${stsName} has policy id ${parsed.id}; the policy file at https://mta-sts.${domain}/.well-known/mta-sts.txt is not fetched`);
    }
  }

  const tlsRecord = selectRecord(tlsFetched, {
    key: 'tls-rpt',
    label: 'TLS-RPT',
    name: tlsName,
    absent: `No TLS-RPT record at ${tlsName}; TLS-RPT is optional and collects reports about failed TLS connections to ${domain}`,
  }, findings);
  if (tlsRecord !== null) {
    result.tlsRpt.record = tlsRecord;
    const parsed = parseTlsRpt(tlsRecord);
    if (parsed.error !== null) {
      info('extras.tls-rpt-invalid', `TLS-RPT record at ${tlsName} is invalid: ${parsed.error}`);
    } else {
      result.tlsRpt.rua = parsed.rua;
      info('extras.tls-rpt-found', `TLS-RPT record at ${tlsName} sends reports to ${parsed.rua.join(', ')}`);
    }
  }

  return result;
}
