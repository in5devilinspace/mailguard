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
