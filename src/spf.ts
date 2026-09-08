// SPF (RFC 7208) record parser and auditor. DNS is used only for the TXT
// record of the domain and of include/redirect targets; a, mx, ptr and exists
// targets are counted toward the lookup limit but never resolved.
import { isIPv4, isIPv6 } from 'node:net';
import type { Finding, Resolver, Severity, SpfSummary } from './types.ts';
import { DnsError } from './types.ts';

export type SpfQualifier = '+' | '-' | '~' | '?';
export type SpfMechanismType = 'all' | 'include' | 'a' | 'mx' | 'ptr' | 'ip4' | 'ip6' | 'exists';

export interface SpfMechanism {
  qualifier: SpfQualifier;
  type: SpfMechanismType;
  value: string | null;
}

export interface SpfModifier {
  name: string;
  value: string;
}

export interface SpfParseResult {
  mechanisms: SpfMechanism[];
  modifiers: SpfModifier[];
  error: string | null;
}

export interface SpfAudit extends SpfSummary {
  findings: Finding[];
}

/** RFC 7208 4.6.4: at most 10 terms that need DNS lookups. */
export const MAX_LOOKUPS = 10;
/** Hard stop so a pathological include graph cannot run forever. */
export const HARD_CAP = 50;

const MECHANISM_TYPES: ReadonlySet<string> = new Set(['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists']);
const COUNTED_TYPES: ReadonlySet<string> = new Set(['include', 'a', 'mx', 'ptr', 'exists']);

export function isSpfRecord(txt: string): boolean {
  const first = txt.trim().split(/\s+/)[0] ?? '';
  return first.toLowerCase() === 'v=spf1';
}

function cidrError(kind: 'ip4' | 'ip6', value: string): string | null {
  const slash = value.indexOf('/');
  const address = slash === -1 ? value : value.slice(0, slash);
  const prefix = slash === -1 ? null : value.slice(slash + 1);
  const valid = kind === 'ip4' ? isIPv4(address) : isIPv6(address);
  if (!valid) return `${kind} mechanism "${kind}:${value}" is not a valid ${kind === 'ip4' ? 'IPv4' : 'IPv6'} address`;
  if (prefix !== null) {
    const max = kind === 'ip4' ? 32 : 128;
    if (!/^\d{1,3}$/.test(prefix) || Number(prefix) > max) {
      return `${kind} mechanism "${kind}:${value}" has a prefix length outside 0-${max}`;
    }
  }
  return null;
}

export function parseSpf(record: string): SpfParseResult {
  const failure = (error: string): SpfParseResult => ({ mechanisms: [], modifiers: [], error });
  const tokens = record.trim().split(/\s+/);
  if ((tokens[0] ?? '').toLowerCase() !== 'v=spf1') return failure('record must start with v=spf1');
  const mechanisms: SpfMechanism[] = [];
  const modifiers: SpfModifier[] = [];
  let sawRedirect = false;
  for (const token of tokens.slice(1)) {
    if (token === '') continue;
    const modifier = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(token);
    if (modifier !== null) {
      const name = (modifier[1] ?? '').toLowerCase();
      const value = modifier[2] ?? '';
      if (name === 'redirect') {
        if (sawRedirect) return failure('duplicate redirect modifier');
        if (value === '') return failure('redirect modifier needs a domain');
        sawRedirect = true;
      }
      // Unknown modifiers are ignored per RFC 7208 6; only redirect and exp are kept.
      if (name === 'redirect' || name === 'exp') modifiers.push({ name, value });
      continue;
    }
    const mechanism = /^([+\-~?])?([a-z0-9]+)(.*)$/i.exec(token);
    if (mechanism === null) return failure(`unknown term "${token}"`);
    const qualifier = (mechanism[1] ?? '+') as SpfQualifier;
    const type = (mechanism[2] ?? '').toLowerCase();
    const rest = mechanism[3] ?? '';
    if (!MECHANISM_TYPES.has(type)) return failure(`unknown mechanism "${token}"`);
    let value: string | null = null;
    if (rest.startsWith(':')) value = rest.slice(1);
    else if (rest.startsWith('/') && (type === 'a' || type === 'mx')) value = rest;
    else if (rest !== '') return failure(`unknown term "${token}"`);
    if (type === 'all' && value !== null) return failure('all mechanism takes no argument');
    if ((type === 'include' || type === 'exists' || type === 'ip4' || type === 'ip6') && (value === null || value === '')) {
      return failure(`${type} mechanism needs an argument`);
    }
    if ((type === 'ip4' || type === 'ip6') && value !== null) {
      const error = cidrError(type, value);
      if (error !== null) return failure(error);
    }
    mechanisms.push({ qualifier, type: type as SpfMechanismType, value });
  }
  return { mechanisms, modifiers, error: null };
}

type FetchResult = { records: string[] } | { errorCode: string };

export async function auditSpf(domain: string, resolver: Resolver): Promise<SpfAudit> {
  const findings: Finding[] = [];
  const state = {
    lookupCount: 0,
    includes: [] as string[],
    redirects: [] as string[],
    allQualifier: null as string | null,
    stopped: false,
  };
  const add = (id: string, severity: Severity, message: string): void => {
    findings.push({ check: 'spf', id, severity, message });
  };
  const summary = (record: string | null, records: string[]): SpfAudit => ({
    record,
    records,
    lookupCount: state.lookupCount,
    allQualifier: state.allQualifier,
    includes: state.includes,
    redirects: state.redirects,
    findings,
  });

  async function fetchSpf(name: string): Promise<FetchResult> {
    try {
      return { records: (await resolver.resolveTxt(name)).filter(isSpfRecord) };
    } catch (err) {
      if (err instanceof DnsError) {
        if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') return { records: [] };
        return { errorCode: err.code };
      }
      throw err;
    }
  }

  function count(): void {
    state.lookupCount += 1;
    if (state.lookupCount > HARD_CAP && !state.stopped) {
      state.stopped = true;
      add('spf.loop', 'error', `SPF evaluation for ${domain} stopped after ${HARD_CAP} DNS lookups because the include or redirect chain is too deep`);
    }
  }

  /** Fetches and evaluates a referenced record; returns false when it could not be used. */
  async function follow(kind: 'include' | 'redirect', target: string, path: string[], isTop: boolean, qualifier: SpfQualifier): Promise<void> {
    const lower = target.toLowerCase();
    if (path.includes(lower)) {
      add('spf.loop', 'error', `SPF ${kind} loop: ${[...path, lower].join(' -> ')}`);
      return;
    }
    const fetched = await fetchSpf(lower);
    if ('errorCode' in fetched) {
      add('spf.lookup-error', 'warning', `TXT lookup for SPF ${kind} target ${lower} failed with ${fetched.errorCode}`);
      return;
    }
    if (fetched.records.length === 0) {
      add('spf.include-missing', 'error', `SPF ${kind} target ${lower} has no SPF record, which is a permanent error for ${domain}`);
      return;
    }
    if (fetched.records.length > 1) {
      add('spf.multiple', 'error', `${lower} publishes multiple SPF records (${fetched.records.length}), which receivers treat as a permanent error`);
      return;
    }
    const parsed = parseSpf(fetched.records[0] ?? '');
    if (parsed.error !== null) {
      add('spf.syntax', 'error', `SPF record at ${lower} has a syntax error: ${parsed.error}`);
      return;
    }
    await evaluate(parsed, lower, [...path, lower], isTop, qualifier);
  }

  async function evaluate(parsed: SpfParseResult, name: string, path: string[], isTop: boolean, includeQualifier: SpfQualifier): Promise<void> {
    for (const mechanism of parsed.mechanisms) {
      if (state.stopped) return;
      if (mechanism.type === 'all') {
        if (isTop) {
          state.allQualifier = mechanism.qualifier;
          if (mechanism.qualifier === '+') {
            add('spf.plus-all', 'error', `SPF record for ${name} ends with +all, which lets any host on the internet send mail as ${domain}`);
          } else if (mechanism.qualifier === '?') {
            add('spf.question-all', 'warning', `SPF record for ${name} ends with ?all, so unlisted senders get a neutral result instead of a fail`);
          }
        } else if (mechanism.qualifier === '+' && includeQualifier === '+') {
          add('spf.plus-all', 'error', `Included record ${name} ends with +all, which makes include:${name} match every sender for ${domain}`);
        }
        // Terms after all are never evaluated and a redirect is ignored (RFC 7208 6.1).
        return;
      }
      if (COUNTED_TYPES.has(mechanism.type)) count();
      if (state.stopped) return;
      if (mechanism.type === 'ptr') {
        add('spf.ptr', 'warning', `SPF record for ${name} uses the ptr mechanism, which RFC 7208 says not to use because it is slow and unreliable`);
      } else if (mechanism.type === 'include') {
        const target = (mechanism.value ?? '').toLowerCase();
        state.includes.push(target);
        await follow('include', target, path, false, mechanism.qualifier);
      }
    }
    const redirect = parsed.modifiers.find((modifier) => modifier.name === 'redirect');
    if (redirect !== undefined && !state.stopped) {
      count();
      if (state.stopped) return;
      const target = redirect.value.toLowerCase();
      state.redirects.push(target);
      await follow('redirect', target, path, isTop, includeQualifier);
    }
  }

  const top = await fetchSpf(domain);
  if ('errorCode' in top) {
    add('spf.lookup-error', 'warning', `TXT lookup for ${domain} failed with ${top.errorCode}, so SPF could not be checked`);
    return summary(null, []);
  }
  if (top.records.length === 0) {
    add('spf.missing', 'error', `${domain} has no SPF record (no TXT record starting with v=spf1)`);
    return summary(null, []);
  }
  if (top.records.length > 1) {
    add('spf.multiple', 'error', `${domain} publishes multiple SPF records (${top.records.length}), which receivers treat as a permanent error`);
    return summary(null, top.records);
  }
  const record = top.records[0] ?? '';
  const parsed = parseSpf(record);
  if (parsed.error !== null) {
    add('spf.syntax', 'error', `SPF record for ${domain} has a syntax error: ${parsed.error}`);
    return summary(record, top.records);
  }
  await evaluate(parsed, domain, [domain.toLowerCase()], true, '+');
  if (!state.stopped) {
    if (state.lookupCount > MAX_LOOKUPS) {
      add('spf.lookups-over-10', 'error', `SPF for ${domain} needs ${state.lookupCount} DNS lookups, more than the 10 DNS lookups receivers allow, so it fails with a permanent error`);
    } else if (state.lookupCount >= 8) {
      add('spf.lookups-8-to-10', 'warning', `SPF for ${domain} needs ${state.lookupCount} of the 10 DNS lookups allowed, leaving little room for growth`);
    }
    if (state.allQualifier === null) {
      add('spf.no-all', 'warning', `SPF record for ${domain} has no all mechanism, so unlisted senders get a neutral result instead of a fail`);
    }
  }
  add('spf.record', 'info', `SPF record for ${domain} is "${record}" and needs ${state.lookupCount} DNS lookups`);
  return summary(record, top.records);
}
