import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const strict = args.includes('--strict');
const requireSmartScreenTracker =
  args.includes('--require-smartscreen-tracker') || truthyEnv(process.env.AEGIS_REQUIRE_SMARTSCREEN_TRACKER);
const jsonOutput = args.includes('--json');
const checks = [];

const packageJson = readJson(join(rootDir, 'package.json'));
const tauriConfig = readJson(join(rootDir, 'src-tauri', 'tauri.conf.json'));
const cargoToml = readFile(join(rootDir, 'src-tauri', 'Cargo.toml'));
const cargoVersion = cargoToml.match(/^version\s*=\s*"([^"]+)"/m)?.[1] ?? null;
const version = packageJson.version;
const releaseDir = join(rootDir, 'release');
const bundleDir = resolveBundleDir();
const releaseNotesPath = join(releaseDir, `Aegis-WebShield-AI-${version}.md`);
const checksumPath = join(releaseDir, `SHA256SUMS-${version}.txt`);
const signatureReportPath = join(releaseDir, 'signature-verification.json');
const smartScreenPackagePath = join(releaseDir, 'smartscreen', `smartscreen-submission-${version}.json`);
const smartScreenTrackerPath = join(releaseDir, 'smartscreen', `smartscreen-tracker-${version}.json`);
const rcSecurityPerformancePath = join(
  releaseDir,
  'rc-security-performance',
  `rc-security-performance-${version}.json`
);
const rcFunctionalE2ePath = join(
  releaseDir,
  'rc-functional-e2e',
  `rc-functional-e2e-${version}.json`
);
const updateManifestPathInput = process.env.AEGIS_UPDATE_MANIFEST_PATH;
const supportDiagnosticsPathInput = process.env.AEGIS_SUPPORT_DIAGNOSTICS_PATH;
const updateManifestPathError = safeRepoPathError(updateManifestPathInput, 'AEGIS_UPDATE_MANIFEST_PATH');
const supportDiagnosticsPathError = safeRepoPathError(supportDiagnosticsPathInput, 'AEGIS_SUPPORT_DIAGNOSTICS_PATH');
const updateManifestPath = updateManifestPathError
  ? null
  : updateManifestPathInput
    ? resolveRepoPath(updateManifestPathInput)
    : join(releaseDir, `update-manifest-${version}.json`);
const supportDiagnosticsPath = supportDiagnosticsPathError
  ? null
  : supportDiagnosticsPathInput
    ? resolveRepoPath(supportDiagnosticsPathInput)
    : join(releaseDir, 'support-diagnostics', `support-diagnostics-${version}.json`);
const allInstallerArtifacts = existsSync(bundleDir)
  ? listFiles(bundleDir).filter((path) => /\.(msi|exe)$/i.test(path))
  : [];
const artifacts = allInstallerArtifacts.filter(isCurrentVersionArtifact);
const staleArtifacts = allInstallerArtifacts.filter((path) => !isCurrentVersionArtifact(path));
const artifactSummaries = artifacts.map((artifact) => ({
  path: toRepoPath(artifact),
  sha256: sha256File(artifact),
  size_bytes: statSync(artifact).size
}));
const installerSmokeReport = latestArtifactEvidenceFile(
  join(releaseDir, 'installer-smoke'),
  /^installer-smoke-.+\.json$/,
  artifactSummaries
);
const appSmokeReports = {
  msi: latestAppSmokeReport(join(releaseDir, 'app-smoke'), 'msi'),
  nsis: latestAppSmokeReport(join(releaseDir, 'app-smoke'), 'nsis')
};

record('version consistency', versionsMatch(), true, `package=${packageJson.version}, tauri=${tauriConfig.version}, cargo=${cargoVersion}`);
record('brand icons', verifyBrandIcons(), true, 'npm run verify:brand-icons');
record('Tauri security config', verifyTauriSecurityConfig(), true, 'npm run verify:tauri-security');
record('RC security/performance evidence', existsSync(rcSecurityPerformancePath), strict, toRepoPath(rcSecurityPerformancePath));
if (existsSync(rcSecurityPerformancePath)) {
  record(
    'RC security/performance verification',
    verifyRcSecurityPerformance(rcSecurityPerformancePath),
    true,
    toRepoPath(rcSecurityPerformancePath)
  );
}
record('RC functional E2E evidence', existsSync(rcFunctionalE2ePath), strict, toRepoPath(rcFunctionalE2ePath));
if (existsSync(rcFunctionalE2ePath)) {
  record(
    'RC functional E2E verification',
    verifyRcFunctionalE2e(rcFunctionalE2ePath),
    true,
    toRepoPath(rcFunctionalE2ePath)
  );
}
record('release notes', existsSync(releaseNotesPath), true, toRepoPath(releaseNotesPath));
record('checksum file', existsSync(checksumPath), strict || artifacts.length > 0, toRepoPath(checksumPath));
record('installer artifacts', artifacts.length > 0, strict, `${artifacts.length} MSI/EXE artifact(s)`);
if (staleArtifacts.length) {
  record('stale installer artifacts excluded', true, false, `${staleArtifacts.length} other-version artifact(s)`);
}
record('signature verification report', existsSync(signatureReportPath), strict, toRepoPath(signatureReportPath));
if (existsSync(signatureReportPath)) {
  record('signature verification result', verifySignatureReport(signatureReportPath), strict, toRepoPath(signatureReportPath));
}
record('installer smoke report', Boolean(installerSmokeReport), strict, installerSmokeReport ? toRepoPath(installerSmokeReport) : 'missing');
if (installerSmokeReport) {
  record(
    'installer install/uninstall smoke result',
    verifyInstallerSmokeReport(installerSmokeReport),
    strict,
    toRepoPath(installerSmokeReport)
  );
}
for (const installer of ['msi', 'nsis']) {
  const report = appSmokeReports[installer];
  record(
    `app smoke ${installer.toUpperCase()} report`,
    Boolean(report),
    strict,
    report ? toRepoPath(report) : 'missing'
  );
  if (report) {
    record(
      `app smoke ${installer.toUpperCase()} result verification`,
      verifyAppSmokeReport(report),
      true,
      toRepoPath(report)
    );
  }
}
record('SmartScreen submission package', existsSync(smartScreenPackagePath), strict, toRepoPath(smartScreenPackagePath));
record('SmartScreen tracker', existsSync(smartScreenTrackerPath), requireSmartScreenTracker, toRepoPath(smartScreenTrackerPath));
if (existsSync(smartScreenTrackerPath)) {
  record(
    'SmartScreen tracker verification',
    verifySmartScreenTracker(smartScreenTrackerPath),
    true,
    toRepoPath(smartScreenTrackerPath)
  );
}
if (updateManifestPathError) {
  record('update manifest path', false, true, updateManifestPathError);
} else {
  record('update manifest', existsSync(updateManifestPath), strict, toRepoPath(updateManifestPath));
  if (existsSync(updateManifestPath)) {
    record('update manifest verification', verifyUpdateManifest(updateManifestPath), true, toRepoPath(updateManifestPath));
  }
}
if (supportDiagnosticsPathError) {
  record('support diagnostics path', false, true, supportDiagnosticsPathError);
} else {
  const supportDiagnosticsRequired = strict || Boolean(supportDiagnosticsPathInput);
  record(
    'support diagnostics evidence',
    existsSync(supportDiagnosticsPath),
    supportDiagnosticsRequired,
    toRepoPath(supportDiagnosticsPath)
  );
  if (existsSync(supportDiagnosticsPath)) {
    record(
      'support diagnostics verification',
      verifySupportDiagnostics(supportDiagnosticsPath),
      true,
      toRepoPath(supportDiagnosticsPath)
    );
  }
}

if (existsSync(smartScreenPackagePath)) {
  const smartScreenPackage = readJson(smartScreenPackagePath);
  record(
    'SmartScreen package version',
    smartScreenPackage.version === version,
    true,
    `package=${smartScreenPackage.version ?? 'missing'}, release=${version}`
  );
  record(
    'SmartScreen package checklist',
    Array.isArray(smartScreenPackage.checklist) && smartScreenPackage.checklist.length > 0,
    true,
    'checklist present'
  );
  verifySmartScreenArtifactCoverage(smartScreenPackage);
}

const failed = checks.filter((check) => check.status === 'failed');
const warnings = checks.filter((check) => check.status === 'warning');
const summary = {
  passed: failed.length === 0,
  strict,
  version,
  checked_at: new Date().toISOString(),
  error_count: failed.length,
  warning_count: warnings.length,
  checks
};

if (jsonOutput) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.log(`Release candidate audit for ${version}: ${summary.passed ? 'passed' : 'failed'}`);
  console.log(`Strict mode: ${strict}`);
  console.log(`Warnings: ${warnings.length}`);
  console.log(`Errors: ${failed.length}`);
  for (const check of checks) {
    console.log(`- ${check.status}: ${check.name}${check.detail ? ` (${check.detail})` : ''}`);
  }
}

if (failed.length) {
  process.exit(2);
}

function record(name, passed, required, detail) {
  checks.push({
    name,
    status: passed ? 'passed' : required ? 'failed' : 'warning',
    required,
    detail
  });
}

function truthyEnv(value) {
  return ['1', 'true', 'yes'].includes(String(value ?? '').toLowerCase());
}

function versionsMatch() {
  return Boolean(packageJson.version && packageJson.version === tauriConfig.version && packageJson.version === cargoVersion);
}

function verifyBrandIcons() {
  const result = spawnSync(process.execPath, ['scripts/verify-brand-icons.mjs', '--json'], {
    cwd: rootDir,
    encoding: 'utf8'
  });
  return result.status === 0;
}

function verifyTauriSecurityConfig() {
  const result = spawnSync(process.execPath, ['scripts/verify-tauri-security-config.mjs', '--json'], {
    cwd: rootDir,
    encoding: 'utf8'
  });
  return result.status === 0;
}

function verifyRcSecurityPerformance(path) {
  const result = spawnSync(
    process.execPath,
    ['scripts/verify-rc-security-performance.mjs', '--file', toRepoPath(path), '--json'],
    { cwd: rootDir, encoding: 'utf8' }
  );
  return result.status === 0;
}

function verifyRcFunctionalE2e(path) {
  const result = spawnSync(
    process.execPath,
    ['scripts/run-rc-functional-e2e.mjs', '--verify', '--file', toRepoPath(path)],
    { cwd: rootDir, encoding: 'utf8' }
  );
  return result.status === 0;
}

function verifyAppSmokeReport(path) {
  const result = spawnSync(process.execPath, ['scripts/verify-app-smoke-result.mjs', '--file', toRepoPath(path), '--json'], {
    cwd: rootDir,
    encoding: 'utf8'
  });
  return result.status === 0;
}

function verifyInstallerSmokeReport(path) {
  const report = readJson(path);
  if (report.install_msi !== true || report.install_nsis !== true) {
    return false;
  }
  const msiArtifacts = artifactSummaries.filter((artifact) => artifact.path.toLowerCase().endsWith('.msi'));
  const nsisArtifacts = artifactSummaries.filter((artifact) => artifact.path.toLowerCase().endsWith('.exe'));
  if (msiArtifacts.length === 0 || nsisArtifacts.length === 0) {
    return false;
  }
  if (!Array.isArray(report.install_results) || report.install_results.length !== msiArtifacts.length) {
    return false;
  }
  if (!Array.isArray(report.nsis_install_results) || report.nsis_install_results.length !== nsisArtifacts.length) {
    return false;
  }
  const msiResults = new Map(
    report.install_results.map((result) => [normalizeRepoPath(result?.artifact ?? ''), result])
  );
  const nsisResults = new Map(
    report.nsis_install_results.map((result) => [normalizeRepoPath(result?.artifact ?? ''), result])
  );
  const validExitCode = (value) => value === 0 || value === 3010;
  const msiPassed = msiArtifacts.every((artifact) => {
    const result = msiResults.get(artifact.path);
    return result
      && typeof result.product_code === 'string'
      && result.product_code.length > 0
      && validExitCode(result.install_exit_code)
      && validExitCode(result.uninstall_exit_code);
  });
  const nsisPassed = nsisArtifacts.every((artifact) => {
    const result = nsisResults.get(artifact.path);
    return result
      && validExitCode(result.install_exit_code)
      && validExitCode(result.uninstall_exit_code)
      && result.remaining_file_count === 0;
  });
  return msiPassed
    && nsisPassed
    && msiResults.size === msiArtifacts.length
    && nsisResults.size === nsisArtifacts.length;
}

function verifySignatureReport(path) {
  const report = readJson(path);
  if (!(report.passed === true &&
    Number.isInteger(report.checked_artifacts) &&
    report.checked_artifacts > 0 &&
    report.failed_artifacts === 0 &&
    Array.isArray(report.artifacts) &&
    report.artifacts.length === report.checked_artifacts &&
    report.artifacts.every((artifact) => artifact.status === 'Valid'))) {
    return false;
  }
  if (artifactSummaries.length > 0 && report.checked_artifacts !== artifactSummaries.length) {
    return false;
  }
  const reportByPath = new Map();
  for (const artifact of report.artifacts) {
    if (!artifact || typeof artifact.path !== 'string') {
      return false;
    }
    const artifactPath = artifact.path.replaceAll('\\', '/');
    if (!isSafeRepoRelativePath(artifactPath) || !isBundleArtifactPath(artifactPath)) {
      return false;
    }
    if (reportByPath.has(artifactPath)) {
      return false;
    }
    reportByPath.set(artifactPath, artifact);
  }
  for (const artifact of artifactSummaries) {
    const signed = reportByPath.get(artifact.path);
    if (!signed) {
      return false;
    }
    if (String(signed.sha256 ?? '').toLowerCase() !== artifact.sha256) {
      return false;
    }
    if (signed.size_bytes !== artifact.size_bytes) {
      return false;
    }
  }
  return reportByPath.size === artifactSummaries.length;
}

function verifySupportDiagnostics(path) {
  const result = spawnSync(process.execPath, ['scripts/verify-support-diagnostics.mjs', toRepoPath(path), '--json'], {
    cwd: rootDir,
    encoding: 'utf8'
  });
  return result.status === 0;
}

function verifyUpdateManifest(path) {
  const result = spawnSync(process.execPath, ['scripts/verify-update-manifest.mjs', '--file', toRepoPath(path), '--json'], {
    cwd: rootDir,
    encoding: 'utf8'
  });
  return result.status === 0;
}

function verifySmartScreenTracker(path) {
  const result = spawnSync(process.execPath, ['scripts/verify-smartscreen-tracker.mjs', '--file', toRepoPath(path), '--json'], {
    cwd: rootDir,
    encoding: 'utf8'
  });
  return result.status === 0;
}

function verifySmartScreenArtifactCoverage(smartScreenPackage) {
  if (!artifacts.length) {
    return;
  }
  const packageArtifacts = Array.isArray(smartScreenPackage.artifacts) ? smartScreenPackage.artifacts : [];
  const packageByPath = new Map(
    packageArtifacts
      .filter((artifact) => artifact && typeof artifact.path === 'string')
      .map((artifact) => [artifact.path.replaceAll('\\', '/'), artifact])
  );
  const missing = artifactSummaries.filter((artifact) => !packageByPath.has(artifact.path));
  const mismatched = artifactSummaries.filter((artifact) => {
    const packaged = packageByPath.get(artifact.path);
    return packaged && String(packaged.sha256).toLowerCase() !== artifact.sha256;
  });
  record(
    'SmartScreen package artifact coverage',
    missing.length === 0 && mismatched.length === 0,
    true,
    `missing=${missing.length}, mismatched=${mismatched.length}`
  );
}

function readJson(path) {
  try {
    return JSON.parse(readFile(path).replace(/^\uFEFF/, ''));
  } catch {
    return {};
  }
}

function readFile(path) {
  return existsSync(path) ? readFileSync(path, 'utf8') : '';
}

function listFiles(dir) {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    const stat = statSync(path);
    return stat.isDirectory() ? listFiles(path) : [path];
  });
}

function resolveBundleDir() {
  const candidates = [
    join(rootDir, 'target', 'release', 'bundle'),
    join(rootDir, 'src-tauri', 'target', 'release', 'bundle')
  ];
  return candidates.find((path) => existsSync(path)) ?? candidates[0];
}

function latestArtifactEvidenceFile(dir, pattern, expectedArtifacts) {
  if (!existsSync(dir) || expectedArtifacts.length === 0) {
    return null;
  }
  return readdirSync(dir)
    .map((entry) => join(dir, entry))
    .filter((path) => statSync(path).isFile() && pattern.test(path.split(/[\\/]/).pop() ?? ''))
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)
    .find((path) => artifactEvidenceMatches(path, expectedArtifacts)) ?? null;
}

function latestAppSmokeReport(dir, installer) {
  if (!existsSync(dir)) {
    return null;
  }
  return readdirSync(dir)
    .map((entry) => join(dir, entry))
    .filter((path) => statSync(path).isFile() && /^app-smoke-.+\.json$/.test(basename(path)))
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)
    .find((path) => {
      const report = readJson(path);
      return report.installer === installer && report.version === version;
    }) ?? null;
}

function artifactEvidenceMatches(path, expectedArtifacts) {
  const report = readJson(path);
  if (!Array.isArray(report.artifacts) || report.artifacts.length !== expectedArtifacts.length) {
    return false;
  }
  const byPath = new Map(
    report.artifacts.map((artifact) => [normalizeRepoPath(artifact?.path ?? ''), artifact])
  );
  return byPath.size === expectedArtifacts.length && expectedArtifacts.every((expected) => {
    const actual = byPath.get(expected.path);
    return actual
      && actual.size_bytes === expected.size_bytes
      && String(actual.sha256 ?? '').toLowerCase() === expected.sha256;
  });
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function toRepoPath(path) {
  return path.replace(rootDir, '').replace(/^[/\\]/, '').replaceAll('\\', '/');
}

function resolveRepoPath(path) {
  return join(rootDir, ...normalizeRepoPath(path).split('/'));
}

function safeRepoPathError(path, label) {
  if (!path) {
    return null;
  }
  if (!isSafeRepoRelativePath(normalizeRepoPath(path))) {
    return `${label} must be a safe repository-relative path.`;
  }
  return null;
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

function isBundleArtifactPath(path) {
  return path.startsWith('target/release/bundle/') || path.startsWith('src-tauri/target/release/bundle/');
}

function isCurrentVersionArtifact(path) {
  return basename(path).includes(`_${version}_`);
}
