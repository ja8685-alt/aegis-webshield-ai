import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const diagnosticsPath = process.env.AEGIS_SUPPORT_DIAGNOSTICS_PATH;
const diagnosticsPathError = diagnosticsPath && !isSafeRepoRelativePath(normalizeRepoPath(diagnosticsPath))
  ? 'AEGIS_SUPPORT_DIAGNOSTICS_PATH must be a safe repository-relative path.'
  : null;
const steps = [
  {
    name: 'frontend build',
    command: npmCommand(),
    args: ['run', 'build']
  },
  {
    name: 'npm audit',
    command: npmCommand(),
    args: ['audit', '--audit-level=moderate']
  },
  {
    name: 'release prepare',
    command: npmCommand(),
    args: ['run', 'release:prepare']
  },
  {
    name: 'release verify',
    command: npmCommand(),
    args: ['run', 'release:verify']
  },
  {
    name: 'release candidate audit',
    command: npmCommand(),
    args: ['run', 'release:audit']
  }
];

if (diagnosticsPath) {
  steps.push({
    name: 'support diagnostics verify',
    command: npmCommand(),
    args: ['run', 'support:verify-diagnostics', '--', diagnosticsPath]
  });
}

const startedAt = Date.now();
const results = [];
if (diagnosticsPathError) {
  results.push({
    name: 'support diagnostics verify',
    status: 'failed',
    exit_code: 2,
    detail: diagnosticsPathError
  });
  finish();
}

for (const step of steps) {
  if (step.name === 'support diagnostics verify' && !existsSync(resolveRepoPath(diagnosticsPath))) {
    results.push({
      name: step.name,
      status: 'failed',
      exit_code: 2,
      detail: `Diagnostics file not found: ${diagnosticsPath}`
    });
    break;
  }

  console.log(`== ${step.name} ==`);
  const result = spawnSync(step.command, step.args, {
    encoding: 'utf8',
    shell: process.platform === 'win32',
    stdio: 'inherit'
  });
  results.push({
    name: step.name,
    status: result.status === 0 ? 'passed' : 'failed',
    exit_code: result.status ?? 1,
    detail: result.error ? result.error.message : undefined
  });
  if (result.status !== 0) {
    break;
  }
}

finish();

function finish() {
  const passed = results.every((result) => result.status === 'passed');
  const summary = {
    passed,
    duration_ms: Date.now() - startedAt,
    diagnostics_checked: Boolean(diagnosticsPath),
    results
  };

  console.log('\nRelease preflight summary');
  console.log(JSON.stringify(summary, null, 2));
  process.exit(passed ? 0 : 2);
}

function npmCommand() {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

function resolveRepoPath(path) {
  return join(rootDir, ...normalizeRepoPath(path).split('/'));
}

function normalizeRepoPath(path) {
  return String(path).replaceAll('\\', '/');
}

function isSafeRepoRelativePath(path) {
  if (!path || path.startsWith('/') || /^[A-Za-z]:/.test(path)) {
    return false;
  }
  return path
    .split('/')
    .every((segment) => segment && segment !== '.' && segment !== '..');
}
