// DKIM (RFC 6376, RFC 8463) selector probing and public key inspection.
import { createPublicKey } from 'node:crypto';
import type { DkimKeyType, DkimSelectorResult, DkimSummary, Finding, Resolver, Severity } from './types.ts';
import { DnsError } from './types.ts';

/** Common selectors published by major providers; --selector adds to this list. */
export const DEFAULT_SELECTORS: readonly string[] = [
  'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'dkim',
  'mail', 'smtp', 'mandrill', 'pm', 'zoho', 'fm1', 'fm2', 'fm3', 'protonmail', 'mailo',
];

export const DEFAULT_CONCURRENCY = 5;
export const RSA_MIN_BITS = 2048;

export interface DkimKeyRecord {
  v: string | null;
  k: string;
  p: string | null;
  t: string[];
  h: string | null;
  n: string | null;
  s: string | null;
  revoked: boolean;
  error: string | null;
}

export interface DkimProbe extends DkimSummary {
  findings: Finding[];
}

export function parseDkimKey(record: string): DkimKeyRecord {
  const result: DkimKeyRecord = { v: null, k: 'rsa', p: null, t: [], h: null, n: null, s: null, revoked: false, error: null };
  const tags: Record<string, string> = {};
  for (const part of record.split(';')) {
    const trimmed = part.trim();
    if (trimmed === '') continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) {
      result.error = `tag "${trimmed}" has no value`;
      return result;
    }
    tags[trimmed.slice(0, eq).trim().toLowerCase()] = trimmed.slice(eq + 1).trim();
  }
  const v = tags['v'];
  if (v !== undefined) {
    result.v = v;
    if (v.toUpperCase() !== 'DKIM1') {
      result.error = `v=${v} is not DKIM1`;
      return result;
    }
  }
  if (tags['p'] === undefined) {
    result.error = 'record has no p tag (public key is required)';
    return result;
  }
  result.k = (tags['k'] ?? 'rsa').toLowerCase();
  // Folding whitespace inside base64 is allowed and must be removed.
  result.p = (tags['p'] ?? '').replace(/\s+/g, '');
  result.revoked = result.p === '';
  result.t = (tags['t'] ?? '').split(':').map((flag) => flag.trim()).filter((flag) => flag !== '');
  result.h = tags['h'] ?? null;
  result.n = tags['n'] ?? null;
  result.s = tags['s'] ?? null;
  return result;
}

export function describeKey(k: string, p: string): { keyType: DkimKeyType; bits: number | null } {
  const unknown = { keyType: 'unknown' as const, bits: null };
  if (!/^[A-Za-z0-9+/=]+$/.test(p)) return unknown;
  const der = Buffer.from(p, 'base64');
  if (k === 'rsa') {
    try {
      const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
      const bits = key.asymmetricKeyDetails?.modulusLength;
      if (key.asymmetricKeyType !== 'rsa' || typeof bits !== 'number') return unknown;
      return { keyType: 'rsa', bits };
    } catch {
      return unknown;
    }
  }
  if (k === 'ed25519') {
    // RFC 8463: p is the raw 32-byte public key, not SPKI.
    return der.length === 32 ? { keyType: 'ed25519', bits: 256 } : unknown;
  }
  return unknown;
}

export function selectorList(extra: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const selector of [...DEFAULT_SELECTORS, ...extra]) {
    const lower = selector.trim().toLowerCase();
    if (lower === '' || seen.has(lower)) continue;
    seen.add(lower);
    out.push(lower);
  }
  return out;
}

interface ProbeOutcome {
  selector: string;
  status: 'found' | 'absent' | 'error';
  errorCode: string | null;
  key: DkimKeyRecord | null;
  keyType: DkimKeyType;
  bits: number | null;
}

async function probeOne(domain: string, selector: string, resolver: Resolver): Promise<ProbeOutcome> {
  const name = `${selector}._domainkey.${domain}`;
  const outcome: ProbeOutcome = { selector, status: 'absent', errorCode: null, key: null, keyType: 'unknown', bits: null };
  let records: string[];
  try {
    records = await resolver.resolveTxt(name);
  } catch (err) {
    if (err instanceof DnsError) {
      if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') return outcome;
      outcome.status = 'error';
      outcome.errorCode = err.code;
      return outcome;
    }
    throw err;
  }
  if (records.length === 0) return outcome;
  outcome.status = 'found';
  // Prefer a record that parses; otherwise keep the first so the failure is reported.
  const parsedAll = records.map(parseDkimKey);
  const key = parsedAll.find((candidate) => candidate.error === null) ?? parsedAll[0] ?? null;
  outcome.key = key;
  if (key !== null && key.error === null && !key.revoked) {
    const described = describeKey(key.k, key.p ?? '');
    outcome.keyType = described.keyType;
    outcome.bits = described.bits;
  }
  return outcome;
}

export async function probeDkim(
  domain: string,
  selectors: readonly string[],
  resolver: Resolver,
  concurrency: number = DEFAULT_CONCURRENCY,
): Promise<DkimProbe> {
  const probed = selectorList(selectors);
  const outcomes: ProbeOutcome[] = new Array(probed.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(concurrency, probed.length)) }, async () => {
    while (next < probed.length) {
      const index = next;
      next += 1;
      outcomes[index] = await probeOne(domain, probed[index] ?? '', resolver);
    }
  });
  await Promise.all(workers);

  const findings: Finding[] = [];
  const add = (id: string, severity: Severity, message: string): void => {
    findings.push({ check: 'dkim', id, severity, message });
  };
  const results: DkimSelectorResult[] = [];
  const sorted = [...outcomes].sort((a, b) => (a.selector < b.selector ? -1 : a.selector > b.selector ? 1 : 0));
  for (const outcome of sorted) {
    const name = `${outcome.selector}._domainkey.${domain}`;
    if (outcome.status === 'error') {
      add('dkim.lookup-error', 'info', `TXT lookup for DKIM selector ${outcome.selector} at ${name} failed with ${outcome.errorCode ?? 'unknown error'}`);
      continue;
    }
    if (outcome.status !== 'found' || outcome.key === null) continue;
    const key = outcome.key;
    const flags = [...key.t];
    if (key.error !== null) {
      results.push({ selector: outcome.selector, keyType: 'unknown', bits: null, revoked: false, flags });
      add('dkim.unparseable', 'warning', `DKIM record at ${name} could not be parsed: ${key.error}`);
      continue;
    }
    if (key.revoked) {
      results.push({ selector: outcome.selector, keyType: 'unknown', bits: null, revoked: true, flags });
      add('dkim.revoked', 'warning', `DKIM selector ${outcome.selector} at ${name} is revoked (empty p= tag)`);
      continue;
    }
    results.push({ selector: outcome.selector, keyType: outcome.keyType, bits: outcome.bits, revoked: false, flags });
    if (outcome.keyType === 'unknown') {
      add('dkim.unparseable', 'warning', `DKIM selector ${outcome.selector} at ${name} has a p= value that does not decode as a ${key.k} public key`);
      continue;
    }
    add('dkim.found', 'info', `DKIM selector ${outcome.selector} at ${name} publishes a ${outcome.keyType} ${outcome.bits}-bit key${flags.length > 0 ? ` (flags ${flags.join(':')})` : ''}`);
    if (outcome.keyType === 'rsa' && outcome.bits !== null && outcome.bits < RSA_MIN_BITS) {
      add('dkim.rsa-weak', 'warning', `DKIM selector ${outcome.selector} uses a ${outcome.bits}-bit RSA key; ${RSA_MIN_BITS} bits or more is expected`);
    }
  }
  const anyFound = sorted.some((outcome) => outcome.status === 'found');
  const anyError = sorted.some((outcome) => outcome.status === 'error');
  if (!anyFound && !anyError) {
    add('dkim.none', 'info', `No DKIM key found under the ${probed.length} probed selectors for ${domain}; pass --selector <name> with the selector your mail provider uses`);
  }
  return { probed, selectors: results, findings };
}
