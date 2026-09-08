// Text and JSON rendering. No color, no timestamps.
import type { DomainReport, Finding, HeadersReport } from './types.ts';

export function toJson(value: unknown): string {
  return JSON.stringify(value, null, 2) + '\n';
}

function findingLine(finding: Finding): string {
  return `  [${finding.severity}] ${finding.message}`;
}

export function formatDomainText(report: DomainReport): string {
  const lines: string[] = [];
  lines.push(`Domain: ${report.domain}`);
  lines.push(`Grade: ${report.grade} (score ${report.score})`);
  const sections: [string, string][] = [['spf', 'SPF'], ['dmarc', 'DMARC'], ['dkim', 'DKIM'], ['mx', 'MX']];
  for (const [check, label] of sections) {
    lines.push('');
    lines.push(label);
    const findings = report.findings.filter((finding) => finding.check === check);
    if (findings.length === 0) lines.push('  (no findings)');
    for (const finding of findings) lines.push(findingLine(finding));
  }
  return lines.join('\n') + '\n';
}

function yesNo(value: boolean): string {
  return value ? 'yes' : 'no';
}

function describeAuth(entry: HeadersReport['authResults'][number]): string {
  if (entry.results.length === 0) return `${entry.authservId ?? '(no authserv-id)'}: none`;
  const parts = entry.results.map((result) => {
    const props = Object.entries(result.properties).map(([key, value]) => `${key}=${value}`);
    const reason = result.reason !== null ? [`reason="${result.reason}"`] : [];
    return [`${result.method}=${result.result}`, ...reason, ...props].join(' ');
  });
  return `${entry.authservId ?? '(no authserv-id)'}: ${parts.join('; ')}`;
}

export function formatHeadersText(report: HeadersReport): string {
  const lines: string[] = [];
  const describeAddress = (address: HeadersReport['from']): string =>
    address.raw === '' ? '(absent)' : `${address.raw}${address.domain !== null ? ` (domain ${address.domain})` : ''}`;
  lines.push(`From: ${describeAddress(report.from)}`);
  lines.push(`Return-Path: ${describeAddress(report.returnPath)}`);
  lines.push('');
  lines.push(`Hops (oldest first): ${report.hops.length}`);
  report.hops.forEach((hop, index) => {
    const delay = index === 0 ? 'start' : hop.delaySeconds === null ? '?' : `${hop.delaySeconds >= 0 ? '+' : ''}${hop.delaySeconds} s`;
    const route = [`from ${hop.from ?? '(local)'}`, `by ${hop.by ?? '(unknown)'}`];
    if (hop.with !== null) route.push(`with ${hop.with}`);
    const flags = hop.flags.length > 0 ? ` [${hop.flags.join(', ')}]` : '';
    lines.push(`  ${index + 1}. ${delay.padEnd(8)} ${route.join(' ')}${flags}`);
  });
  lines.push(`Total transit: ${report.totalTransitSeconds === null ? 'unknown' : `${report.totalTransitSeconds} s`}`);
  lines.push('');
  const verdict = report.verdict;
  lines.push(`Authentication (verdict from ${verdict.authservId ?? 'no header'}): spf=${verdict.spf} dkim=${verdict.dkim} dmarc=${verdict.dmarc}`);
  for (const entry of report.authResults) lines.push(`  ${describeAuth(entry)}`);
  lines.push(`Alignment: ${report.alignment.verdict}`);
  lines.push(`  DKIM d=${report.alignment.dkim.domain ?? '(none)'}: relaxed ${yesNo(report.alignment.dkim.relaxed)}, strict ${yesNo(report.alignment.dkim.strict)}`);
  lines.push(`  SPF domain ${report.alignment.spf.domain ?? '(none)'}: relaxed ${yesNo(report.alignment.spf.relaxed)}, strict ${yesNo(report.alignment.spf.strict)}`);
  lines.push(`DKIM-Signatures: ${report.dkimSignatures.length}`);
  for (const signature of report.dkimSignatures) {
    lines.push(`  d=${signature.d ?? '?'} s=${signature.s ?? '?'} a=${signature.a ?? '?'} c=${signature.c ?? '?'}, From signed: ${yesNo(signature.fromSigned)}`);
  }
  lines.push('');
  lines.push('Findings');
  if (report.findings.length === 0) lines.push('  (none)');
  for (const finding of report.findings) lines.push(findingLine(finding));
  return lines.join('\n') + '\n';
}
