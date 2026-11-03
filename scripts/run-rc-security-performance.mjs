import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const packageJson = JSON.parse(readFileSync(join(rootDir, 'package.json'), 'utf8'));
const version = packageJson.version;
const outputArg = valueAfter('--output') ?? `release/rc-security-performance/rc-security-performance-${version}.json`;
const outputPath = resolveSafeRepoPath(outputArg, '--output');
const cargo = process.env.AEGIS_CARGO_PATH || 'cargo';
const startedAt = new Date();
const allowDirty = args.includes('--allow-dirty');
const sourceTreeClean = gitWorkingTreeClean();

if (!sourceTreeClean && !allowDirty) {
  throw new Error('RC evidence requires a clean Git working tree. Commit the candidate or use --allow-dirty for local-only verification.');
}

const thresholds = {
  passive_p95_case_duration_micros: 50_000,
  active_p95_family_pair_duration_micros: 250_000,
  openapi_p95_import_duration_micros: 5_000_000
};

const suites = [
  runSuite('scope policy', ['test', '-p', 'aegis-core', 'scope::tests']),
  runSuite('HTTP destination isolation', ['test', '-p', 'aegis-native-http']),
  runSuite('evidence redaction', ['test', '-p', 'aegis-native-engine', 'redaction::tests']),
  runSuite('scanner request policy', ['test', '-p', 'aegis-scanner'])
];

if (suites.some((suite) => !suite.passed)) {
  process.exit(2);
}

const passive = runBenchmark('passive detector benchmark', [
  'run', '--quiet', '--release', '-p', 'aegis-native-passive', '--bin', 'passive-benchmark', '--', '--iterations', '1000'
]);
const active = runBenchmark('active candidate benchmark', [
  'run', '--quiet', '--release', '-p', 'aegis-native-active', '--bin', 'active-benchmark', '--', '--iterations', '100'
]);
const openapi = runBenchmark('large OpenAPI benchmark', [
  'run', '--quiet', '--release', '-p', 'aegis-openapi', '--bin', 'openapi-benchmark', '--', '--endpoints', '5000', '--iterations', '3'
]);

const benchmarks = { passive, active, openapi };
const passed = benchmarkGatesPass(benchmarks, thresholds);
const report = {
  schema_version: 'aegis.rc-security-performance.v1',
  product: 'Aegis WebShield AI',
  version,
  source_commit: gitValue(['rev-parse', 'HEAD']),
  source_tree_clean: sourceTreeClean,
  checked_at: new Date().toISOString(),
  duration_millis: Date.now() - startedAt.getTime(),
  platform: `${process.platform}-${process.arch}`,
  rustc_version: commandValue(process.env.AEGIS_RUSTC_PATH || 'rustc', ['--version']),
  passed,
  thresholds,
  suites,
  benchmarks
};

mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
const repoOutputPath = toRepoPath(outputPath);
console.log(`RC security/performance evidence: ${repoOutputPath}`);

const verification = spawnSync(process.execPath, [
  'scripts/verify-rc-security-performance.mjs',
  '--file',
  repoOutputPath,
  ...(allowDirty ? ['--allow-dirty'] : [])
], {
  cwd: rootDir,
  encoding: 'utf8'
});
process.stdout.write(verification.stdout || '');
process.stderr.write(verification.stderr || '');
if (verification.status !== 0 || !passed) {
  process.exit(2);
}

function runSuite(name, cargoArgs) {
  const started = Date.now();
  const result = runCommand(cargo, cargoArgs);
  const suite = {
    name,
    passed: result.status === 0,
    duration_millis: Date.now() - started
  };
  console.log(`- ${suite.passed ? 'passed' : 'failed'}: ${name} (${suite.duration_millis} ms)`);
  if (!suite.passed) {
    printFailure(result);
  }
  return suite;
}

function runBenchmark(name, cargoArgs) {
  const result = runCommand(cargo, cargoArgs);
  if (result.status !== 0) {
    console.error(`${name} failed.`);
    printFailure(result);
    process.exit(2);
  }
  try {
    const report = JSON.parse(result.stdout.trim());
    console.log(`- passed: ${name}`);
    return report;
  } catch (error) {
    console.error(`${name} returned invalid JSON: ${error.message}`);
    process.exit(2);
  }
}

function benchmarkGatesPass(benchmarks, limits) {
  return benchmarks.passive.schema_version === 'aegis.native.passive-benchmark.v1'
    && benchmarks.passive.false_positives === 0
    && benchmarks.passive.false_negatives === 0
    && benchmarks.passive.precision_basis_points === 10_000
    && benchmarks.passive.seeded_coverage_basis_points === 10_000
    && benchmarks.passive.p95_case_duration_micros <= limits.passive_p95_case_duration_micros
    && benchmarks.active.schema_version === 'aegis.native.active-benchmark.v1'
    && benchmarks.active.false_positives === 0
    && benchmarks.active.false_negatives === 0
    && benchmarks.active.precision_basis_points === 10_000
    && benchmarks.active.recall_basis_points === 10_000
    && benchmarks.active.reproduction_basis_points === 10_000
    && benchmarks.active.network_requests === 0
    && benchmarks.active.external_scanner_processes === 0
    && benchmarks.active.destructive_requests === 0
    && benchmarks.active.p95_family_pair_duration_micros <= limits.active_p95_family_pair_duration_micros
    && benchmarks.openapi.schema_version === 'aegis.openapi-benchmark.v1'
    && benchmarks.openapi.endpoints === 5_000
    && benchmarks.openapi.endpoint_limit_enforced === true
    && benchmarks.openapi.network_requests === 0
    && benchmarks.openapi.p95_import_duration_micros <= limits.openapi_p95_import_duration_micros;
}

function runCommand(command, commandArgs) {
  return spawnSync(command, commandArgs, {
    cwd: rootDir,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    env: process.env
  });
}

function gitValue(gitArgs) {
  const value = commandValue('git', gitArgs);
  if (!/^[a-f0-9]{40}$/.test(value)) {
    throw new Error('Unable to determine the current Git commit.');
  }
  return value;
}

function gitWorkingTreeClean() {
  return commandValue('git', ['status', '--porcelain', '--untracked-files=normal']) === '';
}

function commandValue(command, commandArgs) {
  const result = runCommand(command, commandArgs);
  if (result.status !== 0) {
    throw new Error(`Command failed: ${command} ${commandArgs.join(' ')}`);
  }
  return result.stdout.trim();
}

function printFailure(result) {
  const detail = `${result.stderr || ''}\n${result.stdout || ''}`.trim().slice(-4_000);
  if (detail) {
    console.error(detail);
  }
}

function valueAfter(name) {
  const index = args.indexOf(name);
  return index === -1 ? null : args[index + 1] ?? null;
}

function resolveSafeRepoPath(value, label) {
  if (!value || isAbsolute(value)) {
    throw new Error(`${label} must be a safe repository-relative path.`);
  }
  const resolved = resolve(rootDir, value);
  const repoPath = relative(rootDir, resolved).replaceAll('\\', '/');
  if (!repoPath.startsWith('release/rc-security-performance/') || repoPath.includes('/../')) {
    throw new Error(`${label} must resolve under release/rc-security-performance.`);
  }
  return resolved;
}

function toRepoPath(path) {
  return relative(rootDir, path).replaceAll('\\', '/');
}
