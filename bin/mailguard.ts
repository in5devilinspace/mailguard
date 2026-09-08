#!/usr/bin/env node
// Executable entry. The only file that calls process.exit, after stdout has
// been flushed through a write callback so piped JSON is never truncated.
import { main } from '../src/cli.ts';

const code = await main(process.argv.slice(2), {
  stdout: process.stdout,
  stderr: process.stderr,
  stdin: process.stdin,
});
process.stdout.write('', () => process.exit(code));
