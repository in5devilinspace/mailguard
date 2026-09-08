// Offline zone-file resolver for `--zone file.json`. Lets a user dry-run a DNS
// change before publishing it, and gives the tests a network-free resolver.
import { readFileSync } from 'node:fs';
import type { MxRecord, Resolver } from './types.ts';
import { DnsError, ZoneFormatError } from './types.ts';

export interface ZoneEntry {
  /** A string is one record; a string[] is the character-string chunks of one record. */
  TXT?: (string | string[])[];
  MX?: MxRecord[];
  A?: string[];
  AAAA?: string[];
}

export type ZoneData = Record<string, ZoneEntry>;

function normalizeName(name: string): string {
  const lower = name.toLowerCase();
  return lower.endsWith('.') ? lower.slice(0, -1) : lower;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function validateEntry(file: string, name: string, raw: unknown): ZoneEntry {
  if (!isPlainObject(raw)) {
    throw new ZoneFormatError(`zone file ${file}: entry for ${name} must be an object`);
  }
  const entry: ZoneEntry = {};
  for (const key of Object.keys(raw)) {
    const value = raw[key];
    if (key === 'TXT') {
      if (!Array.isArray(value) || !value.every((item) => typeof item === 'string' || isStringArray(item))) {
        throw new ZoneFormatError(`zone file ${file}: TXT for ${name} must be an array of strings or string arrays`);
      }
      entry.TXT = value as (string | string[])[];
    } else if (key === 'MX') {
      if (!Array.isArray(value)) {
        throw new ZoneFormatError(`zone file ${file}: MX for ${name} must be an array`);
      }
      const records: MxRecord[] = [];
      for (const item of value) {
        if (!isPlainObject(item) || typeof item['priority'] !== 'number' || !Number.isInteger(item['priority'])) {
          throw new ZoneFormatError(`zone file ${file}: every MX entry for ${name} needs an integer priority`);
        }
        if (typeof item['exchange'] !== 'string') {
          throw new ZoneFormatError(`zone file ${file}: every MX entry for ${name} needs a string exchange`);
        }
        records.push({ priority: item['priority'], exchange: item['exchange'] });
      }
      entry.MX = records;
    } else if (key === 'A' || key === 'AAAA') {
      if (!isStringArray(value)) {
        throw new ZoneFormatError(`zone file ${file}: ${key} for ${name} must be an array of strings`);
      }
      entry[key] = value;
    } else {
      throw new ZoneFormatError(`zone file ${file}: unknown record type "${key}" for ${name} (use TXT, MX, A or AAAA)`);
    }
  }
  return entry;
}

export function parseZoneData(file: string, raw: unknown): ZoneData {
  if (!isPlainObject(raw)) {
    throw new ZoneFormatError(`zone file ${file}: top level must be an object keyed by domain name`);
  }
  const zone: ZoneData = {};
  for (const name of Object.keys(raw)) {
    zone[normalizeName(name)] = validateEntry(file, name, raw[name]);
  }
  return zone;
}

export function loadZoneFile(file: string): ZoneData {
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new ZoneFormatError(`cannot read zone file ${file}: ${reason}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new ZoneFormatError(`zone file ${file} is not valid JSON: ${reason}`);
  }
  return parseZoneData(file, raw);
}

export function zoneResolver(zone: ZoneData): Resolver {
  function lookup<K extends keyof ZoneEntry>(name: string, type: K): NonNullable<ZoneEntry[K]> {
    const entry = zone[normalizeName(name)];
    if (entry === undefined) throw new DnsError('ENOTFOUND', `${name} does not exist in the zone file`);
    const records = entry[type];
    if (records === undefined || records.length === 0) {
      throw new DnsError('ENODATA', `${name} has no ${type} records in the zone file`);
    }
    return records as NonNullable<ZoneEntry[K]>;
  }
  return {
    async resolveTxt(name) {
      return lookup(name, 'TXT').map((record) => (Array.isArray(record) ? record.join('') : record));
    },
    async resolveMx(name) {
      return lookup(name, 'MX').map((record) => ({ priority: record.priority, exchange: record.exchange }));
    },
    async resolve4(name) {
      return [...lookup(name, 'A')];
    },
    async resolve6(name) {
      return [...lookup(name, 'AAAA')];
    },
  };
}
