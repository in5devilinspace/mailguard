// Argument parsing and dispatch. main() returns the exit code; only
// bin/mailguard.ts calls process.exit.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import type { ParseArgsConfig } from 'node:util';
import { auditDomain } from './audit.ts';
import { exitCodeForGrade } from './grade.ts';
import { formatDomainText, toJson } from './report.ts';
import { DEFAULT_TIMEOUT_MS, systemResolver } from './resolver.ts';
import type { Resolver } from './types.ts';
import { DnsError, DomainNotFoundError, ZoneFormatError } from './types.ts';
import { loadZoneFile, zoneResolver } from './zone.ts';

export interface Writer {
  write(chunk: string): unknown;
}

export interface ResolverOptions {
  timeoutMs: number;
  servers: string[];
}

export interface CliIo {
  stdout: Writer;
  stderr: Writer;
  stdin: AsyncIterable<string | Uint8Array>;
  /** Test seam: replaces the system resolver when --zone is not given. */
  makeResolver?: (options: ResolverOptions) => Resolver;
}

export const VERSION: string = JSON.parse(
  readFileSync(path.join(import.meta.dirname, '..', 'package.json'), 'utf8'),
).version;

const TOP_USAGE = `Usage: mailguard <command> [options]

Commands:
  domain <domain>     Audit SPF, DMARC, DKIM and MX for a domain and grade it
  headers [file | -]  Explain the Received, Authentication-Results and DKIM
                      headers of one message (file or stdin, no network)

Options:
  -h, --help          Show this help and exit 0
  --version           Print the version and exit 0

Exit codes:
  0  grade A or B (domain) or headers parsed
  1  grade C, D or F
  2  usage error, unreadable input, or domain does not resolve
`;

const DOMAIN_USAGE = `Usage: mailguard domain <domain> [options]

Audits SPF, DMARC, DKIM and MX for <domain> and prints a graded report.

Options:
  --json               Print one JSON document on stdout instead of text
  --zone <file.json>   Read DNS answers from an offline zone file instead of
                       the network (dry-run a change before publishing it)
  --selector <name>    Probe this DKIM selector in addition to the defaults
                       (repeatable)
  --timeout <ms>       Per-query DNS timeout, default ${DEFAULT_TIMEOUT_MS}
  --dns <ip>           Resolver address to use instead of the system resolver
                       (repeatable)
  -h, --help           Show this help and exit 0

--zone cannot be combined with --dns or --timeout.

Exit codes:
  0  grade A or B
  1  grade C, D or F
  2  usage error, unreadable or malformed zone file, invalid domain, or the
     domain does not resolve at all
`;

const HEADERS_USAGE = `Usage: mailguard headers [file | -] [options]

Reads RFC 5322 headers from <file> or stdin (no argument or "-"), stops at the
first blank line, and explains Received hops, Authentication-Results, DKIM
signatures and alignment. Never touches the network.

Options:
  --json               Print one JSON document on stdout instead of text
  -h, --help           Show this help and exit 0

Exit codes:
  0  at least one header parsed
  2  usage error, unreadable input, or no headers found
`;

export type Command = 'top' | 'domain' | 'headers';

export function usage(command: Command): string {
  if (command === 'domain') return DOMAIN_USAGE;
  if (command === 'headers') return HEADERS_USAGE;
  return TOP_USAGE;
}

/** Lowercases, strips one trailing dot and checks hostname label syntax. */
export function normalizeDomain(input: string): string | null {
  let domain = input.trim().toLowerCase();
  if (domain.endsWith('.')) domain = domain.slice(0, -1);
  if (domain === '' || domain.length > 253) return null;
  for (const label of domain.split('.')) {
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) return null;
  }
  return domain;
}

function usageError(io: CliIo, command: Command, message: string): number {
  io.stderr.write(`mailguard: ${message}\n\n${usage(command)}`);
  return 2;
}

type ParseOptions = NonNullable<ParseArgsConfig['options']>;

interface ParsedArgs {
  values: Record<string, string | boolean | (string | boolean)[] | undefined>;
  positionals: string[];
}

function safeParse(args: string[], options: ParseOptions): ParsedArgs | { error: string } {
  try {
    const result = parseArgs({ args, options, strict: true, allowPositionals: true });
    return { values: result.values as ParsedArgs['values'], positionals: result.positionals };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

async function runDomain(args: string[], io: CliIo): Promise<number> {
  const parsed = safeParse(args, {
    json: { type: 'boolean' },
    zone: { type: 'string' },
    selector: { type: 'string', multiple: true },
    timeout: { type: 'string' },
    dns: { type: 'string', multiple: true },
    help: { type: 'boolean', short: 'h' },
  });
  if ('error' in parsed) return usageError(io, 'domain', parsed.error);
  const { values, positionals } = parsed;
  if (values['help'] === true) {
    io.stdout.write(usage('domain'));
    return 0;
  }
  const first = positionals[0];
  if (first === undefined) return usageError(io, 'domain', 'missing <domain> argument');
  if (positionals.length > 1) return usageError(io, 'domain', `unexpected argument "${positionals[1]}"`);
  const domain = normalizeDomain(first);
  if (domain === null) return usageError(io, 'domain', `"${first}" is not a valid domain name`);

  const zoneFile = typeof values['zone'] === 'string' ? values['zone'] : null;
  const timeoutRaw = typeof values['timeout'] === 'string' ? values['timeout'] : null;
  const servers = Array.isArray(values['dns']) ? (values['dns'] as string[]) : [];
  const selectors = Array.isArray(values['selector']) ? (values['selector'] as string[]) : [];
  if (zoneFile !== null && (timeoutRaw !== null || servers.length > 0)) {
    return usageError(io, 'domain', '--zone cannot be combined with --dns or --timeout');
  }
  let timeoutMs = DEFAULT_TIMEOUT_MS;
  if (timeoutRaw !== null) {
    if (!/^\d+$/.test(timeoutRaw) || Number(timeoutRaw) <= 0) {
      return usageError(io, 'domain', `--timeout must be a positive integer number of milliseconds, got "${timeoutRaw}"`);
    }
    timeoutMs = Number(timeoutRaw);
  }

  let resolver: Resolver;
  if (zoneFile !== null) {
    try {
      resolver = zoneResolver(loadZoneFile(zoneFile));
    } catch (err) {
      if (err instanceof ZoneFormatError) {
        io.stderr.write(`mailguard: ${err.message}\n`);
        return 2;
      }
      throw err;
    }
  } else {
    const make = io.makeResolver ?? systemResolver;
    resolver = make({ timeoutMs, servers });
  }

  try {
    const report = await auditDomain(domain, resolver, { selectors });
    io.stdout.write(values['json'] === true ? toJson(report) : formatDomainText(report));
    return exitCodeForGrade(report.grade);
  } catch (err) {
    if (err instanceof DomainNotFoundError) {
      io.stderr.write(`mailguard: ${err.message}\n`);
      return 2;
    }
    if (err instanceof DnsError) {
      io.stderr.write(`mailguard: DNS resolver failure (${err.code}): ${err.message}\n`);
      return 2;
    }
    throw err;
  }
}

export async function main(argv: string[], io: CliIo): Promise<number> {
  const first = argv[0];
  if (first === undefined) {
    io.stderr.write(usage('top'));
    return 2;
  }
  if (first === '--help' || first === '-h') {
    io.stdout.write(usage('top'));
    return 0;
  }
  if (first === '--version') {
    io.stdout.write(`mailguard ${VERSION}\n`);
    return 0;
  }
  if (first === 'domain') return runDomain(argv.slice(1), io);
  return usageError(io, 'top', `unknown command "${first}"`);
}
