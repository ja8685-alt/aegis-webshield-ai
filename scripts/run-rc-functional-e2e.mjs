import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const packageJson = readJson(join(rootDir, 'package.json'));
const version = packageJson.version;
const allowDirty = args.includes('--allow-dirty');
const verifyOnly = args.includes('--verify');
const cargo = process.env.AEGIS_CARGO_PATH || 'cargo';
const defaultReport = `release/rc-functional-e2e/rc-functional-e2e-${version}.json`;
const fileArg = valueAfter('--file') ?? defaultReport;
const reportPath = confinedPath(fileArg, '--file');

if (verifyOnly) {
  const summary = verifyEvidence(reportPath, fileArg, allowDirty);
  printSummary(summary);
  if (!summary.passed) process.exit(2);
  process.exit(0);
}

const sourceTreeClean = gitWorkingTreeClean();
if (!sourceTreeClean && !allowDirty) {
  throw new Error('RC functional E2E evidence requires a clean Git working tree. Use --allow-dirty only for local verification.');
}

const fixtureDir = join(rootDir, 'release', 'rc-functional-e2e', 'fixtures');
mkdirSync(fixtureDir, { recursive: true });
const validManifestPath = join(fixtureDir, `valid-update-manifest-${version}.json`);
const invalidManifestPath = join(fixtureDir, `invalid-update-manifest-${version}.json`);
writeFileSync(validManifestPath, `${JSON.stringify(updateManifest(true), null, 2)}\n`, 'utf8');
writeFileSync(invalidManifestPath, `${JSON.stringify(updateManifest(false), null, 2)}\n`, 'utf8');

const suites = [
  runSuite('local scan, report, and unrestricted rule flow', cargo, [
    'test', '-p', 'aegis-cli', '--test', 'rc_functional_e2e'
  ], true),
  runSuite('update manifest acceptance', process.execPath, [
    'scripts/verify-update-manifest.mjs', '--file', toRepoPath(validManifestPath), '--json'
  ], true),
  runSuite('update manifest rejection', process.execPath, [
    'scripts/verify-update-manifest.mjs', '--file', toRepoPath(invalidManifestPath), '--json'
  ], false)
];

const report = {
  schema_version: 'aegis.rc-functional-e2e.v1',
  product: 'Aegis WebShield AI',
  version,
  source_commit: gitHead(),
  source_tree_clean: sourceTreeClean,
  checked_at: new Date().toISOString(),
  passed: suites.every((suite) => suite.passed),
  suites
};
mkdirSync(dirname(reportPath), { recursive: true });
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
const verification = verifyEvidence(reportPath, fileArg, allowDirty);
printSummary(verification);
if (!report.passed || !verification.passed) process.exit(2);

function runSuite(name, command, commandArgs, expectSuccess) {
  const started = Date.now();
  const result = spawnSync(command, commandArgs, {
    cwd: rootDir,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    env: process.env
  });
  const observedSuccess = result.status === 0;
  const passed = observedSuccess === expectSuccess;
  console.log(`- ${passed ? 'passed' : 'failed'}: ${name}`);
  if (!passed) {
    const detail = `${result.stderr || ''}\n${result.stdout || ''}`.trim().slice(-4_000);
    if (detail) console.error(detail);
  }
  return {
    name,
    passed,
    expected_exit: expectSuccess ? 0 : 2,
    observed_exit: result.status,
    duration_millis: Math.max(1, Date.now() - started)
  };
}

function verifyEvidence(path, repoPath, permitDirty) {
  const errors = [];
  let evidence = {};
  if (!existsSync(path)) {
    errors.push(`RC functional E2E evidence not found: ${repoPath}`);
  } else {
    evidence = readJson(path, errors);
  }
  if (!errors.length) {
    if (evidence.schema_version !== 'aegis.rc-functional-e2e.v1') errors.push('invalid schema_version.');
    if (evidence.product !== 'Aegis WebShield AI') errors.push('invalid product.');
    if (evidence.version !== version) errors.push(`version must match ${version}.`);
    if (!/^[a-f0-9]{40}$/.test(evidence.source_commit ?? '')) errors.push('source_commit must be a full Git SHA.');
    if (evidence.source_commit !== gitHead()) errors.push('source_commit must match the current Git commit.');
    if (evidence.source_tree_clean !== true && !permitDirty) errors.push('source_tree_clean must be true.');
    if (!gitWorkingTreeClean() && !permitDirty) errors.push('current Git working tree must be clean.');
    if (evidence.passed !== true) errors.push('passed must be true.');
    if (typeof evidence.checked_at !== 'string' || Number.isNaN(Date.parse(evidence.checked_at))) {
      errors.push('checked_at must be an ISO-8601 timestamp.');
    }
    const required = new Map([
      ['local scan, report, and unrestricted rule flow', 0],
      ['update manifest acceptance', 0],
      ['update manifest rejection', 2]
    ]);
    if (!Array.isArray(evidence.suites) || evidence.suites.length !== required.size) {
      errors.push('all three functional E2E suites are required.');
    } else {
      for (const suite of evidence.suites) {
        const expectedExit = required.get(suite?.name);
        if (expectedExit === undefined || suite.passed !== true || suite.expected_exit !== expectedExit
          || suite.observed_exit !== expectedExit || !Number.isInteger(suite.duration_millis)
          || suite.duration_millis <= 0) {
          errors.push('functional E2E suite evidence is invalid.');
          break;
        }
        required.delete(suite.name);
      }
      if (required.size) errors.push('one or more functional E2E suites are missing.');
    }
  }
  return { passed: errors.length === 0, file: repoPath, version: evidence.version ?? null, errors };
}

function updateManifest(valid) {
  return {
    product: 'Aegis WebShield AI',
    version,
    channel: 'stable',
    pub_date: '2026-08-01T00:00:00Z',
    platforms: {
      'windows-x86_64': {
        url: valid
          ? `https://downloads.example.com/aegis/${version}/Aegis-WebShield-AI.exe`
          : `http://downloads.example.com/aegis/${version}/Aegis-WebShield-AI.exe?token=unsafe`,
        sha256: 'a'.repeat(64),
        signature: valid ? 'b'.repeat(64) : 'short',
        size_bytes: 1024
      }
    }
  };
}

function printSummary(summary) {
  console.log(`RC functional E2E evidence verification: ${summary.passed ? 'passed' : 'failed'}`);
  console.log(`Evidence: ${summary.file}`);
  summary.errors.forEach((error) => console.log(`- ${error}`));
}

function readJson(path, errors = []) {
  try {
    return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
  } catch (error) {
    errors.push(`Unable to parse JSON: ${error.message}`);
    return {};
  }
}

function valueAfter(name) {
  const index = args.indexOf(name);
  return index === -1 ? null : args[index + 1] ?? null;
}

function confinedPath(value, label) {
  if (!value || isAbsolute(value)) throw new Error(`${label} must be repository-relative.`);
  const resolved = resolve(rootDir, value);
  const repoPath = toRepoPath(resolved);
  if (!repoPath.startsWith('release/rc-functional-e2e/') || repoPath.includes('/../')) {
    throw new Error(`${label} must resolve under release/rc-functional-e2e.`);
  }
  return resolved;
}

function gitHead() {
  const result = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: rootDir, encoding: 'utf8' });
  const value = result.status === 0 ? result.stdout.trim() : '';
  if (!/^[a-f0-9]{40}$/.test(value)) throw new Error('Unable to determine current Git commit.');
  return value;
}

function gitWorkingTreeClean() {
  const result = spawnSync('git', ['status', '--porcelain', '--untracked-files=normal'], {
    cwd: rootDir,
    encoding: 'utf8'
  });
  return result.status === 0 && result.stdout.trim() === '';
}

function toRepoPath(path) {
  return relative(rootDir, path).replaceAll('\\', '/');
}
