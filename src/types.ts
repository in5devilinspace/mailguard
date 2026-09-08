// Shared types and error classes. No runtime logic lives here beyond the
// error constructors, so any module can import from this file without
// pulling in DNS, file or CLI code.

export type Severity = 'error' | 'warning' | 'info';

export type DomainCheck = 'spf' | 'dmarc' | 'dkim' | 'mx' | 'extras';
export type HeaderCheck = 'received' | 'auth' | 'alignment' | 'dkim-signature' | 'return-path';

export interface Finding {
  check: DomainCheck | HeaderCheck;
  id: string;
  severity: Severity;
  message: string;
}

export interface MxRecord {
  priority: number;
  exchange: string;
}

/** Every DNS-touching module takes one of these; only src/resolver.ts builds a real one. */
export interface Resolver {
  /** Each element is one TXT record with its character-strings already concatenated. */
  resolveTxt(name: string): Promise<string[]>;
  resolveMx(name: string): Promise<MxRecord[]>;
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
}

export class DnsError extends Error {
  code: string;
  constructor(code: string, message?: string) {
    super(message ?? `DNS error ${code}`);
    this.name = 'DnsError';
    this.code = code;
  }
}

export class DomainNotFoundError extends Error {
  domain: string;
  constructor(domain: string) {
    super(`${domain} does not resolve (NXDOMAIN for TXT, MX, A and AAAA)`);
    this.name = 'DomainNotFoundError';
    this.domain = domain;
  }
}

export class ZoneFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ZoneFormatError';
  }
}

export class HeadersInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HeadersInputError';
  }
}

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface SpfSummary {
  record: string | null;
  records: string[];
  lookupCount: number;
  allQualifier: string | null;
  includes: string[];
  redirects: string[];
}

export interface DmarcSummary {
  record: string | null;
  source: string | null;
  inherited: boolean;
  policy: string | null;
  subdomainPolicy: string | null;
  effectivePolicy: string | null;
  pct: number | null;
  rua: string[];
}

export type DkimKeyType = 'rsa' | 'ed25519' | 'unknown';

export interface DkimSelectorResult {
  selector: string;
  keyType: DkimKeyType;
  bits: number | null;
  revoked: boolean;
  flags: string[];
}

export interface DkimSummary {
  probed: string[];
  selectors: DkimSelectorResult[];
}

export interface MxHost {
  priority: number;
  exchange: string;
  addresses: string[];
}

export interface MxSummary {
  nullMx: boolean;
  records: MxHost[];
}

/** BIMI, MTA-STS and TLS-RPT presence. Informational only; never graded. */
export interface ExtrasSummary {
  bimi: { record: string | null; location: string | null; authority: string | null };
  mtaSts: { record: string | null; id: string | null };
  tlsRpt: { record: string | null; rua: string[] };
}

export interface DomainReport {
  domain: string;
  grade: Grade;
  score: number;
  checks: {
    spf: SpfSummary;
    dmarc: DmarcSummary;
    dkim: DkimSummary;
    mx: MxSummary;
    extras: ExtrasSummary;
  };
  findings: Finding[];
}

export interface Address {
  raw: string;
  address: string | null;
  domain: string | null;
}

export interface Hop {
  from: string | null;
  by: string | null;
  with: string | null;
  id: string | null;
  for: string | null;
  date: string | null;
  timestamp: string | null;
  delaySeconds: number | null;
  flags: string[];
}

export interface AuthResultEntry {
  method: string;
  result: string;
  reason: string | null;
  properties: Record<string, string>;
}

export interface AuthResults {
  authservId: string | null;
  results: AuthResultEntry[];
}

export interface AlignmentSide {
  domain: string | null;
  relaxed: boolean;
  strict: boolean;
}

export interface DkimSignatureSummary {
  d: string | null;
  s: string | null;
  a: string | null;
  c: string | null;
  fromSigned: boolean;
}

export interface HeadersReport {
  from: Address;
  returnPath: Address;
  hops: Hop[];
  totalTransitSeconds: number | null;
  authResults: AuthResults[];
  verdict: {
    authservId: string | null;
    spf: string;
    dkim: string;
    dmarc: string;
  };
  alignment: {
    dkim: AlignmentSide;
    spf: AlignmentSide;
    verdict: 'aligned' | 'misaligned' | 'unknown';
  };
  dkimSignatures: DkimSignatureSummary[];
  findings: Finding[];
}
