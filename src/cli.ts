import { readFileSync } from 'node:fs';
import path from 'node:path';

export interface Writer {
  write(chunk: string): unknown;
}

export interface CliIo {
  stdout: Writer;
  stderr: Writer;
  stdin: AsyncIterable<string | Uint8Array>;
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

export function usage(command: 'top' | 'domain' | 'headers'): string {
  return TOP_USAGE;
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
  io.stderr.write(`mailguard: unknown command "${first}"\n\n${usage('top')}`);
  return 2;
}
