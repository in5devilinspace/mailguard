// Email header analysis: Received hops, Authentication-Results, DKIM-Signature
// and identifier alignment. Pure parsing; no DNS and no network.
import { organizationalDomain } from './dmarc.ts';
import type {
  Address,
  AlignmentSide,
  AuthResultEntry,
  AuthResults,
  DkimSignatureSummary,
  Finding,
  HeadersReport,
  Hop,
  Severity,
} from './types.ts';
import { HeadersInputError } from './types.ts';

export interface Header {
  name: string;
  value: string;
}

/** Delay above which a hop is flagged as slow. */
export const SLOW_HOP_SECONDS = 300;

/**
 * Splits a header block into name/value pairs. Accepts CRLF or LF, unfolds
 * continuation lines, skips one leading Unix "From " envelope line and stops
 * at the first blank line so a body is never read.
 */
export function parseHeaderBlock(text: string): Header[] {
  const lines = text.split(/\r\n|\n|\r/);
  const headers: Header[] = [];
  let index = 0;
  if ((lines[0] ?? '').startsWith('From ')) index = 1;
  for (; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    if (line.trim() === '') break;
    if (/^[ \t]/.test(line)) {
      const last = headers[headers.length - 1];
      if (last !== undefined) last.value = `${last.value} ${line.trim()}`.trim();
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim();
    if (!/^[!-9;-~]+$/.test(name)) continue;
    headers.push({ name, value: line.slice(colon + 1).trim() });
  }
  if (headers.length === 0) throw new HeadersInputError('no headers found in input');
  return headers;
}

/** Removes RFC 5322 comments, including nested ones, outside quoted strings. */
export function stripComments(text: string): string {
  let out = '';
  let depth = 0;
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i] ?? '';
    if (quoted) {
      out += ch;
      if (ch === '\\' && i + 1 < text.length) {
        out += text[i + 1] ?? '';
        i += 1;
      } else if (ch === '"') {
        quoted = false;
      }
      continue;
    }
    if (ch === '"' && depth === 0) {
      quoted = true;
      out += ch;
    } else if (ch === '(') {
      depth += 1;
    } else if (ch === ')') {
      depth = Math.max(0, depth - 1);
    } else if (depth === 0) {
      out += ch;
    }
  }
  return out;
}

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
const NAMED_ZONES: Record<string, number> = {
  UT: 0, GMT: 0, EST: -300, EDT: -240, CST: -360, CDT: -300, MST: -420, MDT: -360, PST: -480, PDT: -420,
};
const DATE_RE = /^(?:(?:mon|tue|wed|thu|fri|sat|sun),?\s+)?(\d{1,2})\s+([a-z]{3})\s+(\d{2}|\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s+([+-]\d{4}|[a-z]{1,3}))?$/i;

/** Strict RFC 5322 date parser. Returns epoch milliseconds or null; never falls back to Date.parse. */
export function parseRfc5322Date(input: string): number | null {
  const text = stripComments(input).replace(/\s+/g, ' ').trim();
  const match = DATE_RE.exec(text);
  if (match === null) return null;
  const day = Number(match[1]);
  const month = MONTHS.indexOf((match[2] ?? '').toLowerCase());
  if (month === -1) return null;
  const yearText = match[3] ?? '';
  let year = Number(yearText);
  if (yearText.length === 2) year += year < 50 ? 2000 : 1900;
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = match[6] !== undefined ? Number(match[6]) : 0;
  if (day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) return null;
  let offsetMinutes = 0;
  const zone = match[7];
  if (zone !== undefined) {
    if (/^[+-]\d{4}$/.test(zone)) {
      const hours = Number(zone.slice(1, 3));
      const minutes = Number(zone.slice(3, 5));
      if (hours > 23 || minutes > 59) return null;
      offsetMinutes = (zone.startsWith('-') ? -1 : 1) * (hours * 60 + minutes);
    } else {
      const named = NAMED_ZONES[zone.toUpperCase()];
      if (named !== undefined) offsetMinutes = named;
      else if (zone.length !== 1) return null;
      // Single-letter military zones carry no usable offset (RFC 5322 4.3): treat as +0000.
    }
  }
  const utc = Date.UTC(year, month, day, hour, minute, second);
  if (new Date(utc).getUTCMonth() !== month) return null;
  return utc - offsetMinutes * 60_000;
}

export interface ReceivedClauses {
  from: string | null;
  by: string | null;
  with: string | null;
  id: string | null;
  for: string | null;
  via: string | null;
  date: string | null;
  raw: string;
}

type ClauseKey = 'from' | 'by' | 'with' | 'id' | 'for' | 'via';
const CLAUSE_KEYS: ReadonlySet<string> = new Set(['from', 'by', 'with', 'id', 'for', 'via']);

/** Splits text on whitespace at parenthesis depth 0 so comments stay attached to their token. */
function tokenizeKeepingComments(text: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let depth = 0;
  for (const ch of text) {
    if (ch === '(') depth += 1;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    if (/\s/.test(ch) && depth === 0) {
      if (current !== '') tokens.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  if (current !== '') tokens.push(current);
  return tokens;
}

/** Tolerant Received parser: clause keywords at depth 0 split the value; the date follows the last ';'. */
export function parseReceived(value: string): ReceivedClauses {
  const raw = value.trim();
  let depth = 0;
  let quoted = false;
  let lastSemicolon = -1;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    if (ch === '"' && depth === 0) quoted = !quoted;
    else if (!quoted) {
      if (ch === '(') depth += 1;
      else if (ch === ')') depth = Math.max(0, depth - 1);
      else if (ch === ';' && depth === 0) lastSemicolon = i;
    }
  }
  const dateText = lastSemicolon === -1 ? '' : raw.slice(lastSemicolon + 1).trim();
  const clauseText = lastSemicolon === -1 ? raw : raw.slice(0, lastSemicolon);
  const parts: Record<ClauseKey, string[]> = { from: [], by: [], with: [], id: [], for: [], via: [] };
  const seen = new Set<ClauseKey>();
  let current: ClauseKey | null = null;
  for (const token of tokenizeKeepingComments(clauseText)) {
    const lower = token.toLowerCase();
    if (CLAUSE_KEYS.has(lower) && !seen.has(lower as ClauseKey)) {
      current = lower as ClauseKey;
      seen.add(current);
      continue;
    }
    if (current !== null) parts[current].push(token);
  }
  const join = (key: ClauseKey): string | null => (parts[key].length === 0 ? null : parts[key].join(' '));
  const forToken = parts.for[0] ?? null;
  return {
    from: join('from'),
    by: join('by'),
    with: join('with'),
    id: join('id'),
    for: forToken === null ? null : forToken.replace(/^<|>$/g, ''),
    via: join('via'),
    date: dateText === '' ? null : dateText,
    raw,
  };
}

/** Splits on a separator outside quoted strings and comments. */
function splitOutside(text: string, separator: string): string[] {
  const out: string[] = [];
  let current = '';
  let depth = 0;
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i] ?? '';
    if (quoted) {
      current += ch;
      if (ch === '\\' && i + 1 < text.length) {
        current += text[i + 1] ?? '';
        i += 1;
      } else if (ch === '"') {
        quoted = false;
      }
      continue;
    }
    if (ch === '"' && depth === 0) {
      quoted = true;
      current += ch;
    } else if (ch === '(') {
      depth += 1;
      current += ch;
    } else if (ch === ')') {
      depth = Math.max(0, depth - 1);
      current += ch;
    } else if (ch === separator && depth === 0) {
      out.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  out.push(current);
  return out;
}

/** Whitespace tokenizer that removes comments and unquotes quoted strings. */
function tokenizeAuth(text: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let hasToken = false;
  let depth = 0;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i] ?? '';
    if (depth > 0) {
      if (ch === '(') depth += 1;
      else if (ch === ')') depth -= 1;
      continue;
    }
    if (ch === '"') {
      hasToken = true;
      i += 1;
      while (i < text.length && text[i] !== '"') {
        if (text[i] === '\\' && i + 1 < text.length) i += 1;
        current += text[i] ?? '';
        i += 1;
      }
      continue;
    }
    if (ch === '(') {
      depth = 1;
      continue;
    }
    if (/\s/.test(ch)) {
      if (hasToken) tokens.push(current);
      current = '';
      hasToken = false;
      continue;
    }
    current += ch;
    hasToken = true;
  }
  if (hasToken) tokens.push(current);
  return tokens;
}

export function parseAuthResults(value: string): AuthResults {
  const segments = splitOutside(value, ';').map((segment) => segment.trim()).filter((segment) => segment !== '');
  let authservId: string | null = null;
  let start = 0;
  const firstTokens = tokenizeAuth(segments[0] ?? '');
  if (firstTokens.length > 0 && !(firstTokens[0] ?? '').includes('=')) {
    authservId = firstTokens[0] ?? null;
    start = 1;
  }
  const results: AuthResultEntry[] = [];
  for (const segment of segments.slice(start)) {
    const tokens = tokenizeAuth(segment);
    const head = tokens[0];
    if (head === undefined || !head.includes('=')) continue;
    const eq = head.indexOf('=');
    const method = head.slice(0, eq).split('/')[0]?.toLowerCase() ?? '';
    const result = head.slice(eq + 1).toLowerCase();
    if (method === '') continue;
    const entry: AuthResultEntry = { method, result, reason: null, properties: {} };
    for (const token of tokens.slice(1)) {
      const split = token.indexOf('=');
      if (split === -1) continue;
      const key = token.slice(0, split).toLowerCase();
      const val = token.slice(split + 1);
      if (key === 'reason') entry.reason = val;
      else entry.properties[key] = val;
    }
    results.push(entry);
  }
  return { authservId, results };
}

export function parseDkimSignature(value: string): DkimSignatureSummary {
  const tags: Record<string, string> = {};
  for (const part of value.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim();
  }
  const signed = (tags['h'] ?? '').split(':').map((name) => name.trim().toLowerCase());
  return {
    d: tags['d'] !== undefined ? tags['d'].toLowerCase() : null,
    s: tags['s'] ?? null,
    a: tags['a'] ?? null,
    c: tags['c'] ?? null,
    fromSigned: signed.includes('from'),
  };
}

export function parseAddress(value: string): Address {
  const raw = value.trim();
  if (raw === '') return { raw, address: null, domain: null };
  const angle = /<([^>]*)>/.exec(raw);
  let address: string;
  if (angle !== null) {
    address = (angle[1] ?? '').trim();
  } else {
    const bare = stripComments(raw).trim();
    address = bare.split(/\s+/).find((token) => token.includes('@')) ?? bare;
  }
  const at = address.lastIndexOf('@');
  const domain = at === -1 ? '' : address.slice(at + 1).toLowerCase();
  return { raw, address, domain: domain === '' ? null : domain };
}

function firstHeader(headers: Header[], name: string): string | null {
  const lower = name.toLowerCase();
  return headers.find((header) => header.name.toLowerCase() === lower)?.value ?? null;
}

function allHeaders(headers: Header[], name: string): string[] {
  const lower = name.toLowerCase();
  return headers.filter((header) => header.name.toLowerCase() === lower).map((header) => header.value);
}

function domainOf(identifier: string | undefined): string | null {
  if (identifier === undefined || identifier === '') return null;
  const at = identifier.lastIndexOf('@');
  const domain = (at === -1 ? identifier : identifier.slice(at + 1)).toLowerCase();
  return domain === '' ? null : domain;
}

function alignmentSide(fromDomain: string | null, other: string | null): AlignmentSide {
  if (fromDomain === null || other === null) return { domain: other, relaxed: false, strict: false };
  return {
    domain: other,
    relaxed: organizationalDomain(fromDomain) === organizationalDomain(other),
    strict: fromDomain === other,
  };
}

export function analyzeHeaders(text: string): HeadersReport {
  const headers = parseHeaderBlock(text);
  const findings: Finding[] = [];
  const add = (check: Finding['check'], id: string, severity: Severity, message: string): void => {
    findings.push({ check, id, severity, message });
  };

  const from = parseAddress(firstHeader(headers, 'From') ?? '');
  const returnPath = parseAddress(firstHeader(headers, 'Return-Path') ?? '');

  const received = allHeaders(headers, 'Received').map(parseReceived).reverse();
  const hops: Hop[] = [];
  let previous: number | null = null;
  let total: number | null = null;
  received.forEach((clauses, index) => {
    const epoch = clauses.date === null ? null : parseRfc5322Date(clauses.date);
    const flags: string[] = [];
    let delay: number | null = null;
    if (epoch === null) {
      flags.push('no-date');
    } else if (index > 0 && previous !== null) {
      delay = Math.round((epoch - previous) / 1000);
      if (delay < 0) flags.push('clock-skew');
      else if (delay > SLOW_HOP_SECONDS) flags.push('slow');
      total = (total ?? 0) + delay;
    }
    hops.push({
      from: clauses.from,
      by: clauses.by,
      with: clauses.with,
      id: clauses.id,
      for: clauses.for,
      date: clauses.date,
      timestamp: epoch === null ? null : new Date(epoch).toISOString(),
      delaySeconds: delay,
      flags,
    });
    const label = `Hop ${index + 1} (by ${clauses.by ?? 'unknown host'})`;
    if (epoch === null) {
      add('received', 'received.no-date', 'warning', `${label} has no parseable date${clauses.date === null ? '' : ` ("${clauses.date}")`}`);
    } else if (delay !== null && delay < 0) {
      add('received', 'received.clock-skew', 'warning', `${label} is dated ${-delay} s before hop ${index}, so a server clock is wrong`);
    } else if (delay !== null && delay > SLOW_HOP_SECONDS) {
      add('received', 'received.slow', 'warning', `${label} waited ${delay} s after hop ${index}, above the ${SLOW_HOP_SECONDS} s threshold`);
    }
    previous = epoch ?? previous;
  });

  const authResults = allHeaders(headers, 'Authentication-Results').map(parseAuthResults);
  const top = authResults[0];
  const resultFor = (method: string): string => top?.results.find((entry) => entry.method === method)?.result ?? 'none';
  const verdict = {
    authservId: top?.authservId ?? null,
    spf: resultFor('spf'),
    dkim: resultFor('dkim'),
    dmarc: resultFor('dmarc'),
  };
  if (top === undefined) {
    add('auth', 'auth.none', 'info', 'no Authentication-Results header found');
  } else {
    const who = top.authservId ?? 'unnamed verifier';
    for (const entry of top.results) {
      const detail = `${entry.method}=${entry.result} in Authentication-Results from ${who}${entry.reason !== null ? ` (${entry.reason})` : ''}`;
      if (entry.result === 'fail' || entry.result === 'permerror') add('auth', 'auth.fail', 'error', detail);
      else if (entry.result === 'softfail' || entry.result === 'temperror') add('auth', 'auth.softfail', 'warning', detail);
    }
  }

  const dkimSignatures = allHeaders(headers, 'DKIM-Signature').map(parseDkimSignature);
  const dkimEntry = top?.results.find((entry) => entry.method === 'dkim');
  const dkimDomain = domainOf(dkimEntry?.properties['header.d']) ?? domainOf(dkimEntry?.properties['header.i']) ?? dkimSignatures[0]?.d ?? null;
  const spfEntry = top?.results.find((entry) => entry.method === 'spf');
  const spfDomain = domainOf(spfEntry?.properties['smtp.mailfrom']) ?? returnPath.domain;
  const dkimSide = alignmentSide(from.domain, dkimDomain);
  const spfSide = alignmentSide(from.domain, spfDomain);
  let alignmentVerdict: HeadersReport['alignment']['verdict'] = 'unknown';
  if (dkimSide.relaxed || spfSide.relaxed) alignmentVerdict = 'aligned';
  else if (from.domain !== null && (dkimDomain !== null || spfDomain !== null)) alignmentVerdict = 'misaligned';

  if (from.domain !== null && dkimDomain !== null && !dkimSide.relaxed) {
    add('alignment', 'alignment.dkim', 'warning', `DKIM d=${dkimDomain} does not align with the From domain ${from.domain}, even in relaxed mode`);
  }
  if (from.domain !== null && spfDomain !== null && !spfSide.relaxed) {
    add('alignment', 'alignment.spf', 'warning', `SPF domain ${spfDomain} (smtp.mailfrom or Return-Path) does not align with the From domain ${from.domain}, even in relaxed mode`);
  }
  for (const signature of dkimSignatures) {
    if (!signature.fromSigned) {
      add('dkim-signature', 'dkim-signature.from-unsigned', 'warning', `DKIM-Signature d=${signature.d ?? 'unknown'} s=${signature.s ?? 'unknown'} does not cover the From header in its h= list`);
    }
  }
  if (from.domain !== null && returnPath.domain !== null && returnPath.domain !== from.domain) {
    add('return-path', 'return-path.differs', 'info', `Return-Path domain ${returnPath.domain} differs from the From domain ${from.domain}, which is common for bulk senders and bounce handling`);
  }

  return {
    from,
    returnPath,
    hops,
    totalTransitSeconds: total,
    authResults,
    verdict,
    alignment: { dkim: dkimSide, spf: spfSide, verdict: alignmentVerdict },
    dkimSignatures,
    findings,
  };
}
