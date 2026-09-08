// MX audit: record presence, null MX (RFC 7505), IP literal exchanges and
// whether each exchange resolves to an address.
import { isIPv4, isIPv6 } from 'node:net';
import type { Finding, MxHost, MxSummary, Resolver, Severity } from './types.ts';
import { DnsError } from './types.ts';

export interface MxAudit extends MxSummary {
  findings: Finding[];
}

export function isIpLiteral(host: string): boolean {
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  return isIPv4(bare) || isIPv6(bare);
}

function stripDot(name: string): string {
  return name.length > 1 && name.endsWith('.') ? name.slice(0, -1) : name;
}

type AddressResult = { addresses: string[] } | { errorCode: string };

async function resolveAddresses(resolver: Resolver, name: string): Promise<AddressResult> {
  const query = async (run: () => Promise<string[]>): Promise<AddressResult> => {
    try {
      return { addresses: await run() };
    } catch (err) {
      if (err instanceof DnsError) {
        if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') return { addresses: [] };
        return { errorCode: err.code };
      }
      throw err;
    }
  };
  const [v4, v6] = await Promise.all([query(() => resolver.resolve4(name)), query(() => resolver.resolve6(name))]);
  if ('errorCode' in v4) return v4;
  if ('errorCode' in v6) return v6;
  return { addresses: [...v4.addresses, ...v6.addresses] };
}

export async function auditMx(domain: string, resolver: Resolver): Promise<MxAudit> {
  const findings: Finding[] = [];
  const add = (id: string, severity: Severity, message: string): void => {
    findings.push({ check: 'mx', id, severity, message });
  };
  const result: MxAudit = { nullMx: false, records: [], findings };

  let raw: { priority: number; exchange: string }[];
  try {
    raw = await resolver.resolveMx(domain);
  } catch (err) {
    if (!(err instanceof DnsError)) throw err;
    if (err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') {
      add('mx.lookup-error', 'warning', `MX lookup for ${domain} failed with ${err.code}, so mail routing could not be checked`);
      return result;
    }
    raw = [];
  }
  const sorted = raw
    .map((record) => ({ priority: record.priority, exchange: stripDot(record.exchange) }))
    .sort((a, b) => a.priority - b.priority || (a.exchange < b.exchange ? -1 : a.exchange > b.exchange ? 1 : 0));

  if (sorted.length === 0) {
    const apex = await resolveAddresses(resolver, domain);
    if ('errorCode' in apex) {
      add('mx.lookup-error', 'warning', `${domain} has no MX record and its address lookup failed with ${apex.errorCode}`);
    } else if (apex.addresses.length > 0) {
      add('mx.missing-a-present', 'warning', `${domain} has no MX record, so mail falls back to its A/AAAA address (${apex.addresses.length} found) under the implicit MX rule`);
    } else {
      add('mx.missing-no-a', 'error', `${domain} has no MX record and no A or AAAA address, so it cannot receive mail at all`);
    }
    return result;
  }

  if (sorted.length === 1 && sorted[0]?.priority === 0 && sorted[0]?.exchange === '.') {
    result.nullMx = true;
    result.records = [{ priority: 0, exchange: '.', addresses: [] }];
    add('mx.null', 'info', `${domain} publishes a null MX (priority 0, exchange ".") and does not accept mail`);
    return result;
  }

  const hosts: MxHost[] = [];
  for (const record of sorted) {
    const host: MxHost = { priority: record.priority, exchange: record.exchange, addresses: [] };
    hosts.push(host);
    if (isIpLiteral(record.exchange)) {
      add('mx.ip-literal', 'error', `MX host ${record.exchange} (priority ${record.priority}) is an IP literal, but MX exchanges must be hostnames`);
      continue;
    }
    const resolved = await resolveAddresses(resolver, record.exchange);
    if ('errorCode' in resolved) {
      add('mx.lookup-error', 'warning', `Address lookup for MX host ${record.exchange} failed with ${resolved.errorCode}`);
    } else {
      host.addresses = resolved.addresses;
    }
    if (host.addresses.length === 0) {
      add('mx.host-unresolvable', 'error', `MX host ${record.exchange} (priority ${record.priority}) does not resolve to any A or AAAA address`);
    } else {
      add('mx.addresses', 'info', `MX host ${record.exchange} (priority ${record.priority}) resolves to ${host.addresses.length} address${host.addresses.length === 1 ? '' : 'es'}`);
    }
  }
  result.records = hosts;
  return result;
}
