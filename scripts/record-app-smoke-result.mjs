import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const jsonOutput = args.includes('--json');
const allChecksPassed = args.includes('--all-checks-passed');
const installer = valueAfter('--installer');
const checkedBy = valueAfter('--checked-by');
const artifactPathArg = valueAfter('--artifact-path');
const outArg = valueAfter('--out');
const notes = valueAfter('--notes') ?? 'All installed app smoke checks completed.';
const packageJson = JSON.parse(readText(join(rootDir, 'package.json')));
const version = packageJson.version;
const allowedInstallers = new Set(['msi', 'nsis']);
const checkFlags = [
  ['app_launched', '--app-launched'],
  ['version_visible', '--version-visible'],
  ['brand_icon_visible', '--brand-icon-visible'],
  ['credential_manager_save_delete_passed', '--credential-manager-save-delete-passed'],
  ['scan_dashboard_loaded', '--scan-dashboard-loaded'],
  ['audit_log_redaction_checked', '--audit-log-redaction-checked']
];
const errors = [];

if (!installer || !allowedInstallers.has(installer)) {
  errors.push('Missing or invalid --installer. Use "msi" or "nsis".');
}
if (!checkedBy || !checkedBy.trim()) {
  errors.push('Missing required --checked-by <operator> argument.');
}
if (hasSensitiveText(notes)) {
  errors.push('--notes must not include URLs, API keys, tokens, passwords, customer data, or target details.');
}
if (outArg && !isSafeRepoRelativePath(normalizeRepoPath(outArg))) {
  errors.push('--out must be a safe repository-relative path.');
}
if (artifactPathArg && !isSafeRepoRelativePath(normalizeRepoPath(artifactPathArg))) {
  errors.push('--artifact-path must be a safe repository-relative path.');
}

const confirmations = Object.fromEntries(
  checkFlags.map(([field, flag]) => [field, allChecksPassed || args.includes(flag)])
);
const missingFlags = checkFlags.filter(([field]) => confirmations[field] !== true).map(([, flag]) => flag);
if (missingFlags.length) {
  errors.push(`Missing required smoke confirmation flag(s): ${missingFlags.join(', ')}. Use --all-checks-passed only after manual verification.`);
}

let outputPath = null;
const installerArtifactPath = resolveInstallerArtifactPath();
if (installerArtifactPath && installer) {
  const artifactRepoPath = toRepoPath(installerArtifactPath).toLowerCase();
  if (!isBundleArtifactPath(artifactRepoPath)) {
    errors.push('Installer artifact must be under target/release/bundle or src-tauri/target/release/bundle.');
  }
  if (installer === 'msi' && (!artifactRepoPath.endsWith('.msi') || !artifactRepoPath.includes('/msi/'))) {
    errors.push('msi smoke result must reference a .msi artifact under an msi bundle directory.');
  }
  if (installer === 'nsis' && (!artifactRepoPath.endsWith('.exe') || !artifactRepoPath.includes('/nsis/'))) {
    errors.push('nsis smoke result must reference a .exe artifact under an nsis bundle directory.');
  }
  if (!isCurrentVersionArtifact(installerArtifactPath)) {
    errors.push(`Installer artifact filename must match current package version ${version}.`);
  }
}
if (!errors.length) {
  outputPath = outArg ? resolveRepoPath(outArg) : defaultOutputPath(installer, version);
  const artifactStat = statSync(installerArtifactPath);
  const result = {
    product: 'Aegis WebShield AI',
    version,
    installer,
    artifact_path: toRepoPath(installerArtifactPath),
    artifact_sha256: sha256File(installerArtifactPath),
    artifact_size_bytes: artifactStat.size,
    checked_at: new Date().toISOString(),
    checked_by: checkedBy.trim(),
    app_launched: confirmations.app_launched,
    version_visible: confirmations.version_visible,
    brand_icon_visible: confirmations.brand_icon_visible,
    credential_manager_save_delete_passed: confirmations.credential_manager_save_delete_passed,
    scan_dashboard_loaded: confirmations.scan_dashboard_loaded,
    audit_log_redaction_checked: confirmations.audit_log_redaction_checked,
    notes
  };
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  const verification = spawnSync(process.execPath, ['scripts/verify-app-smoke-result.mjs', '--file', toRepoPath(outputPath), '--json'], {
    cwd: rootDir,
    encoding: 'utf8'
  });
  if (verification.status !== 0) {
    errors.push(`Generated app smoke result failed verification: ${verification.stdout || verification.stderr}`.trim());
  }
}

const summary = {
  passed: errors.length === 0,
  file: outputPath ? toRepoPath(outputPath) : null,
  installer: installer ?? null,
  artifact: installerArtifactPath ? toRepoPath(installerArtifactPath) : null,
  version,
  error_count: errors.length,
  errors
};

if (jsonOutput) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.log(`App smoke result recording: ${summary.passed ? 'passed' : 'failed'}`);
  if (summary.file) {
    console.log(`File: ${summary.file}`);
  }
  if (errors.length) {
    console.log('\nErrors:');
    errors.forEach((error) => console.log(`- ${error}`));
  }
}

if (errors.length) {
  process.exit(2);
}

function defaultOutputPath(selectedInstaller, selectedVersion) {
  return join(rootDir, 'release', 'app-smoke', `app-smoke-${selectedVersion}-${selectedInstaller}-${timestampSlug()}.json`);
}

function resolveInstallerArtifactPath() {
  if (artifactPathArg && isSafeRepoRelativePath(normalizeRepoPath(artifactPathArg))) {
    const resolved = resolveRepoPath(artifactPathArg);
    if (!existsSync(resolved)) {
      errors.push(`Installer artifact not found: ${artifactPathArg}`);
      return null;
    }
    if (!statSync(resolved).isFile()) {
      errors.push(`Installer artifact must be a file: ${artifactPathArg}`);
      return null;
    }
    return resolved;
  }

  if (!installer || !allowedInstallers.has(installer)) {
    return null;
  }

  const artifact = latestInstallerArtifact(installer);
  if (!artifact) {
    errors.push(`No ${installer} artifact found under ${toRepoPath(resolveBundleDir())}. Run npm run bundle:windows first.`);
    return null;
  }
  return artifact;
}

function latestInstallerArtifact(selectedInstaller) {
  const bundleDir = resolveBundleDir();
  if (!existsSync(bundleDir)) {
    return null;
  }
  const extension = selectedInstaller === 'msi' ? '.msi' : '.exe';
  const marker = selectedInstaller === 'msi' ? '/msi/' : '/nsis/';
  return listFiles(bundleDir)
    .filter((path) => normalizeRepoPath(path).includes(marker)
      && path.toLowerCase().endsWith(extension)
      && isCurrentVersionArtifact(path))
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0] ?? null;
}

function resolveBundleDir() {
  const candidates = [
    join(rootDir, 'target', 'release', 'bundle'),
    join(rootDir, 'src-tauri', 'target', 'release', 'bundle')
  ];
  return candidates.find((path) => existsSync(path)) ?? candidates[0];
}

function listFiles(dir) {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    const stat = statSync(path);
    return stat.isDirectory() ? listFiles(path) : [path];
  });
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function timestampSlug() {
  return new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

function toRepoPath(path) {
  const absolute = isAbsolute(path) ? path : resolve(rootDir, path);
  return relative(rootDir, absolute).replaceAll('\\', '/');
}

function resolveRepoPath(path) {
  return resolve(rootDir, ...normalizeRepoPath(path).split('/'));
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

function hasSensitiveText(value) {
  return /https?:\/\/|api[_ -]?key|password|token|secret|customer|email|phone|target|evidence|prompt/i.test(String(value));
}

function valueAfter(name) {
  const index = args.indexOf(name);
  if (index === -1) {
    return null;
  }
  return args[index + 1] ?? null;
}

function readText(path) {
  return readFileSync(path, 'utf8');
}
