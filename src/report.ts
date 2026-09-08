// Text and JSON rendering. No color, no timestamps.
import type { DomainReport, Finding } from './types.ts';

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
