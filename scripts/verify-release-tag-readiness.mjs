import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const jsonOutput = args.includes('--json');
const packageJson = readJson(join(rootDir, 'package.json'));
const tauriConfig = readJson(join(rootDir, 'src-tauri', 'tauri.conf.json'));
const cargoToml = readFileSync(join(rootDir, 'src-tauri', 'Cargo.toml'), 'utf8');
const cargoVersion = cargoToml.match(/^version\s*=\s*"([^"]+)"/m)?.[1] ?? null;
const version = packageJson.version;
const expectedVersion = valueAfter('--expected-version') ?? version;
const tag = `v${expectedVersion}`;
const checks = [];

record('version consistency', Boolean(version && version === tauriConfig.version && version === cargoVersion), {
  package: version ?? null,
  tauri: tauriConfig.version ?? null,
  cargo: cargoVersion
});
record('expected version', version === expectedVersion, { expected: expectedVersion, actual: version ?? null });
record('stable v1 version', stableV1(version), { version: version ?? null });
record('clean working tree', git(['status', '--porcelain', '--untracked-files=normal']).stdout.trim() === '', null);

const branch = git(['branch', '--show-current']);
record('release branch', branch.status === 0 && branch.stdout.trim() === 'main', {
  expected: 'main',
  actual: branch.stdout.trim() || null
});

const upstream = git(['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{upstream}']);
record('upstream configured', upstream.status === 0 && Boolean(upstream.stdout.trim()), {
  upstream: upstream.stdout.trim() || null
});
if (upstream.status === 0) {
  const divergence = git(['rev-list', '--left-right', '--count', 'HEAD...@{upstream}']);
  const counts = divergence.stdout.trim().split(/\s+/).map(Number);
  record('upstream synchronized', divergence.status === 0 && counts.length === 2 && counts[0] === 0 && counts[1] === 0, {
    ahead: Number.isFinite(counts[0]) ? counts[0] : null,
    behind: Number.isFinite(counts[1]) ? counts[1] : null
  });
}

const localTag = git(['rev-parse', '--quiet', '--verify', `refs/tags/${tag}`]);
record('local tag available', localTag.status !== 0, { tag });
const remoteTag = git(['ls-remote', '--exit-code', '--tags', 'origin', `refs/tags/${tag}`]);
record('remote tag available', remoteTag.status === 2, {
  tag,
  remote_reachable: remoteTag.status === 0 || remoteTag.status === 2
});

recordCommand('release verification', process.execPath, ['scripts/verify-release.mjs', '--json']);
recordCommand('strict release audit', process.execPath, ['scripts/audit-release-candidate.mjs', '--strict', '--json']);

const failed = checks.filter((check) => !check.passed);
const summary = {
  schema_version: 'aegis.release-tag-readiness.v1',
  passed: failed.length === 0,
  version: version ?? null,
  expected_version: expectedVersion ?? null,
  tag,
  commit: git(['rev-parse', 'HEAD']).stdout.trim() || null,
  checked_at: new Date().toISOString(),
  failed_check_count: failed.length,
  checks
};

if (jsonOutput) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.log(`Release tag readiness for ${tag}: ${summary.passed ? 'passed' : 'failed'}`);
  for (const check of checks) {
    console.log(`- ${check.passed ? 'passed' : 'failed'}: ${check.name}`);
  }
  if (summary.passed) {
    console.log(`Ready for an annotated release tag at commit ${summary.commit}.`);
  }
}

if (!summary.passed) process.exit(2);

function stableV1(value) {
  const match = typeof value === 'string' ? value.match(/^(\d+)\.(\d+)\.(\d+)$/) : null;
  return Boolean(match && Number(match[1]) >= 1);
}

function record(name, passed, detail) {
  checks.push({ name, passed, detail });
}

function recordCommand(name, command, commandArgs) {
  const started = Date.now();
  const result = spawnSync(command, commandArgs, {
    cwd: rootDir,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    env: process.env
  });
  record(name, result.status === 0, {
    exit_code: result.status,
    duration_millis: Math.max(1, Date.now() - started)
  });
}

function git(commandArgs) {
  return spawnSync('git', commandArgs, {
    cwd: rootDir,
    encoding: 'utf8',
    maxBuffer: 2 * 1024 * 1024
  });
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
  } catch {
    return {};
  }
}

function valueAfter(name) {
  const index = args.indexOf(name);
  return index === -1 ? null : args[index + 1] ?? null;
}
