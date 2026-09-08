// Test-only helpers. Not a test file (no .test suffix) so the runner glob skips it.
import { spawn } from 'node:child_process';
import path from 'node:path';

export const repoRoot = path.resolve(import.meta.dirname, '..');
export const binPath = path.join(repoRoot, 'bin', 'mailguard.ts');

export interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Runs bin/mailguard.ts in a child process with the repo root as cwd. */
export function runCli(args: string[], options: { stdin?: string } = {}): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [binPath, ...args], {
      cwd: repoRoot,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => { stdout += chunk; });
    child.stderr.on('data', (chunk: string) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(options.stdin ?? '');
  });
}

/** Drops Node runtime warnings (for example the type-stripping notice on some versions). */
export function withoutNodeWarnings(stderr: string): string {
  return stderr
    .split('\n')
    .filter((line) => !line.startsWith('(node:') && !line.startsWith('(Use `node --trace-warnings'))
    .join('\n');
}

import { readFileSync } from 'node:fs';
import type { CliIo } from '../src/cli.ts';
import type { Resolver, MxRecord } from '../src/types.ts';
import { DnsError } from '../src/types.ts';
import type { ZoneData, ZoneEntry } from '../src/zone.ts';

export function loadZone(name: string): ZoneData {
  return JSON.parse(readFileSync(path.join(repoRoot, 'test', 'fixtures', 'zones', `${name}.json`), 'utf8'));
}

/** Derives a zone from another: null removes a name, an object replaces that name's record types. */
export function variant(zone: ZoneData, overrides: Record<string, ZoneEntry | null>): ZoneData {
  const copy: ZoneData = structuredClone(zone);
  for (const [name, entry] of Object.entries(overrides)) {
    if (entry === null) delete copy[name];
    else copy[name] = { ...(copy[name] ?? {}), ...entry };
  }
  return copy;
}

export function readEml(name: string): string {
  return readFileSync(path.join(repoRoot, 'test', 'fixtures', 'eml', name), 'utf8');
}

export interface SpyResolver {
  resolver: Resolver;
  queries: { type: 'TXT' | 'MX' | 'A' | 'AAAA'; name: string }[];
  maxInFlight: number;
}

/** Wraps a resolver, recording every query and the peak number of concurrent queries. */
export function spyResolver(inner: Resolver): SpyResolver {
  const spy: SpyResolver = { resolver: inner, queries: [], maxInFlight: 0 };
  let inFlight = 0;
  const track = async <T>(type: SpyResolver['queries'][number]['type'], name: string, run: () => Promise<T>): Promise<T> => {
    spy.queries.push({ type, name });
    inFlight += 1;
    spy.maxInFlight = Math.max(spy.maxInFlight, inFlight);
    try {
      return await run();
    } finally {
      inFlight -= 1;
    }
  };
  spy.resolver = {
    resolveTxt: (name) => track('TXT', name, () => inner.resolveTxt(name)),
    resolveMx: (name) => track('MX', name, () => inner.resolveMx(name)),
    resolve4: (name) => track('A', name, () => inner.resolve4(name)),
    resolve6: (name) => track('AAAA', name, () => inner.resolve6(name)),
  };
  return spy;
}

/** A resolver whose promises never settle, for timeout tests. */
export function hangingResolver(): Resolver {
  const never = () => new Promise<never>(() => {});
  return { resolveTxt: never, resolveMx: never, resolve4: never, resolve6: never };
}

/** A resolver that throws DnsError(code) for every query. */
export function throwingResolver(code: string): Resolver {
  const fail = () => Promise.reject(new DnsError(code, `fake ${code}`));
  return { resolveTxt: fail, resolveMx: fail, resolve4: fail, resolve6: fail };
}

/** Builds a resolver from plain functions, defaulting each type to ENODATA. */
export function fakeResolver(parts: Partial<Resolver>): Resolver {
  const nodata = () => Promise.reject(new DnsError('ENODATA'));
  return {
    resolveTxt: parts.resolveTxt ?? nodata,
    resolveMx: parts.resolveMx ?? (nodata as () => Promise<MxRecord[]>),
    resolve4: parts.resolve4 ?? nodata,
    resolve6: parts.resolve6 ?? nodata,
  };
}

export interface MemoryIo {
  io: CliIo;
  stdout(): string;
  stderr(): string;
}

/** An in-process CliIo that buffers output; makeResolver replaces the system resolver so no test touches the network. */
export function memoryIo(options: { stdin?: string; makeResolver?: CliIo['makeResolver'] } = {}): MemoryIo {
  let out = '';
  let err = '';
  async function* stdin(): AsyncGenerator<string> {
    if (options.stdin !== undefined) yield options.stdin;
  }
  return {
    io: {
      stdout: { write: (chunk: string) => { out += chunk; return true; } },
      stderr: { write: (chunk: string) => { err += chunk; return true; } },
      stdin: stdin(),
      makeResolver: options.makeResolver,
    },
    stdout: () => out,
    stderr: () => err,
  };
}
