import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const fileArg = valueAfter('--file');
const jsonOutput = args.includes('--json');
const allowDirty = args.includes('--allow-dirty');
const errors = [];
const packageJson = readJson(join(rootDir, 'package.json'));
let report = {};

if (!fileArg) {
  errors.push('Missing required --file <path> argument.');
} else if (!isSafeRepoRelativePath(fileArg)) {
  errors.push('--file must be a safe repository-relative path.');
} else {
  const filePath = resolve(rootDir, fileArg);
  if (!existsSync(filePath)) {
    errors.push(`RC security/performance evidence not found: ${fileArg}`);
  } else {
    report = readJson(filePath);
  }
}

if (!errors.length) {
  verifyReport(report);
}

const summary = {
  passed: errors.length === 0,
  file: fileArg ?? null,
  version: typeof report.version === 'string' ? report.version : null,
  source_commit: typeof report.source_commit === 'string' ? report.source_commit : null,
  error_count: errors.length,
  errors
};

if (jsonOutput) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.log(`RC security/performance evidence verification: ${summary.passed ? 'passed' : 'failed'}`);
  errors.forEach((error) => console.log(`- ${error}`));
}
if (errors.length) {
  process.exit(2);
}

function verifyReport(value) {
  if (value.schema_version !== 'aegis.rc-security-performance.v1') {
    errors.push('schema_version must be aegis.rc-security-performance.v1.');
  }
  if (value.product !== 'Aegis WebShield AI') {
    errors.push('product must be Aegis WebShield AI.');
  }
  if (value.version !== packageJson.version) {
    errors.push(`version must match current package version ${packageJson.version}.`);
  }
  if (!/^[a-f0-9]{40}$/.test(value.source_commit ?? '')) {
    errors.push('source_commit must be a full Git commit SHA.');
  } else {
    const currentCommit = gitHead();
    if (!currentCommit) {
      errors.push('unable to determine the current Git commit.');
    } else if (value.source_commit !== currentCommit) {
      errors.push(`source_commit must match current Git commit ${currentCommit}.`);
    }
  }
  if (value.source_tree_clean !== true && !allowDirty) {
    errors.push('source_tree_clean must be true for release evidence.');
  }
  if (!gitWorkingTreeClean() && !allowDirty) {
    errors.push('the current Git working tree must be clean when release evidence is verified.');
  }
  if (typeof value.checked_at !== 'string' || Number.isNaN(Date.parse(value.checked_at))) {
    errors.push('checked_at must be an ISO-8601 timestamp.');
  }
  if (value.passed !== true) {
    errors.push('passed must be true.');
  }
  if (!Array.isArray(value.suites) || value.suites.length !== 4) {
    errors.push('suites must contain the four required RC security suites.');
  } else {
    const requiredNames = new Set([
      'scope policy',
      'HTTP destination isolation',
      'evidence redaction',
      'scanner request policy'
    ]);
    for (const suite of value.suites) {
      if (!requiredNames.delete(suite?.name) || suite.passed !== true || !positiveInteger(suite.duration_millis)) {
        errors.push('every required RC security suite must pass with a positive duration.');
        break;
      }
    }
    if (requiredNames.size) {
      errors.push('one or more required RC security suites are missing.');
    }
  }
  verifyThresholds(value.thresholds);
  verifyPassive(value.benchmarks?.passive, value.thresholds);
  verifyActive(value.benchmarks?.active, value.thresholds);
  verifyOpenApi(value.benchmarks?.openapi, value.thresholds);
}

function verifyThresholds(value) {
  for (const [field, maximum] of Object.entries({
    passive_p95_case_duration_micros: 50_000,
    active_p95_family_pair_duration_micros: 250_000,
    openapi_p95_import_duration_micros: 5_000_000
  })) {
    if (!positiveInteger(value?.[field]) || value[field] > maximum) {
      errors.push(`${field} must be a positive integer no greater than ${maximum}.`);
    }
  }
}

function verifyPassive(value, thresholds) {
  if (value?.schema_version !== 'aegis.native.passive-benchmark.v1'
    || value.iterations !== 1_000
    || value.false_positives !== 0
    || value.false_negatives !== 0
    || value.precision_basis_points !== 10_000
    || value.seeded_coverage_basis_points !== 10_000
    || !Array.isArray(value.mismatched_case_ids)
    || value.mismatched_case_ids.length !== 0
    || !within(value.p95_case_duration_micros, thresholds?.passive_p95_case_duration_micros)) {
    errors.push('passive benchmark must meet the RC accuracy and p95 performance gate.');
  }
}

function verifyActive(value, thresholds) {
  if (value?.schema_version !== 'aegis.native.active-benchmark.v1'
    || value.iterations !== 100
    || value.false_positives !== 0
    || value.false_negatives !== 0
    || value.precision_basis_points !== 10_000
    || value.recall_basis_points !== 10_000
    || value.reproduction_basis_points !== 10_000
    || value.network_requests !== 0
    || value.external_scanner_processes !== 0
    || value.destructive_requests !== 0
    || !Array.isArray(value.mismatched_case_ids)
    || value.mismatched_case_ids.length !== 0
    || !within(value.p95_family_pair_duration_micros, thresholds?.active_p95_family_pair_duration_micros)) {
    errors.push('active benchmark must meet the RC safety, accuracy, reproduction, and p95 performance gate.');
  }
}

function verifyOpenApi(value, thresholds) {
  if (value?.schema_version !== 'aegis.openapi-benchmark.v1'
    || value.endpoints !== 5_000
    || value.iterations !== 3
    || value.endpoint_limit_enforced !== true
    || value.network_requests !== 0
    || !within(value.p95_import_duration_micros, thresholds?.openapi_p95_import_duration_micros)) {
    errors.push('OpenAPI benchmark must import 5,000 endpoints within the RC p95 gate and enforce the endpoint limit.');
  }
}

function within(value, maximum) {
  return positiveInteger(value) && positiveInteger(maximum) && value <= maximum;
}

function positiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

function gitHead() {
  const result = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: rootDir, encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : null;
}

function gitWorkingTreeClean() {
  const result = spawnSync('git', ['status', '--porcelain', '--untracked-files=normal'], {
    cwd: rootDir,
    encoding: 'utf8'
  });
  return result.status === 0 && result.stdout.trim() === '';
}

function readJson(path) {
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

function isSafeRepoRelativePath(value) {
  if (!value || isAbsolute(value)) {
    return false;
  }
  const resolved = resolve(rootDir, value);
  const repoPath = relative(rootDir, resolved).replaceAll('\\', '/');
  return repoPath.startsWith('release/rc-security-performance/') && !repoPath.includes('/../');
}
