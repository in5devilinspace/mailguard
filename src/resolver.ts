// The only module that touches node:dns. Everything else receives a Resolver.
import { Resolver as NodeResolver } from 'node:dns/promises';
import type { MxRecord, Resolver } from './types.ts';
import { DnsError } from './types.ts';

/** The subset of node's promise-based resolver that mailguard uses. */
export interface DnsLike {
  resolveTxt(name: string): Promise<string[][]>;
  resolveMx(name: string): Promise<MxRecord[]>;
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
}

export const DEFAULT_TIMEOUT_MS = 5000;

function toDnsError(err: unknown, name: string): DnsError {
  if (err instanceof DnsError) return err;
  if (typeof err === 'object' && err !== null && typeof (err as { code?: unknown }).code === 'string') {
    const code = (err as { code: string }).code;
    return new DnsError(code, `DNS query for ${name} failed with ${code}`);
  }
  const reason = err instanceof Error ? err.message : String(err);
  return new DnsError('EUNKNOWN', `DNS query for ${name} failed: ${reason}`);
}

function withTimeout<T>(query: Promise<T>, timeoutMs: number, name: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(new DnsError('ETIMEOUT', `DNS query for ${name} timed out after ${timeoutMs} ms`));
    }, timeoutMs);
    timer.unref();
  });
  // A late rejection from the abandoned query must not surface as unhandled.
  query.catch(() => {});
  return Promise.race([query, timeout]).finally(() => clearTimeout(timer));
}

export function wrapDns(dns: DnsLike, timeoutMs: number = DEFAULT_TIMEOUT_MS): Resolver {
  async function run<T>(name: string, query: () => Promise<T>): Promise<T> {
    try {
      return await withTimeout(query(), timeoutMs, name);
    } catch (err) {
      throw toDnsError(err, name);
    }
  }
  return {
    resolveTxt: (name) => run(name, async () => (await dns.resolveTxt(name)).map((chunks) => chunks.join(''))),
    resolveMx: (name) =>
      run(name, async () =>
        (await dns.resolveMx(name)).map((record) => ({
          priority: record.priority,
          exchange: record.exchange === '' ? '.' : record.exchange,
        })),
      ),
    resolve4: (name) => run(name, () => dns.resolve4(name)),
    resolve6: (name) => run(name, () => dns.resolve6(name)),
  };
}

export interface SystemResolverOptions {
  timeoutMs?: number;
  servers?: string[];
}

export function systemResolver(options: SystemResolverOptions = {}): Resolver {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const resolver = new NodeResolver({ timeout: timeoutMs, tries: 1 });
  if (options.servers !== undefined && options.servers.length > 0) {
    resolver.setServers(options.servers);
  }
  return wrapDns(resolver, timeoutMs);
}
