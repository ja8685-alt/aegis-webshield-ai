import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const fileArg = valueAfter('--file');
const jsonOutput = args.includes('--json');
const errors = [];
const allowedInstallers = new Set(['msi', 'nsis']);
const packageJson = readJson(join(rootDir, 'package.json'));
const currentVersion = typeof packageJson.version === 'string' ? packageJson.version : null;

if (!fileArg) {
  errors.push('Missing required --file <path> argument.');
} else if (!isSafeRepoRelativePath(normalizeRepoPath(fileArg))) {
  errors.push('--file must be a safe repository-relative path.');
}

const filePath = fileArg && isSafeRepoRelativePath(normalizeRepoPath(fileArg)) ? resolveRepoPath(fileArg) : null;
let result = {};
if (filePath && !existsSync(filePath)) {
  errors.push(`App smoke result not found: ${fileArg}`);
} else if (filePath) {
  result = readJson(filePath);
}

if (!errors.length) {
  verifyResult(result);
}

const summary = {
  passed: errors.length === 0,
  file: fileArg ?? null,
  product: typeof result.product === 'string' ? result.product : null,
  version: typeof result.version === 'string' ? result.version : null,
  installer: typeof result.installer === 'string' ? result.installer : null,
  error_count: errors.length,
  errors
};

if (jsonOutput) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.log(`App smoke result verification: ${summary.passed ? 'passed' : 'failed'}`);
  if (summary.version) {
    console.log(`Version: ${summary.version}`);
  }
  if (summary.installer) {
    console.log(`Installer: ${summary.installer}`);
  }
  if (errors.length) {
    console.log('\nErrors:');
    errors.forEach((error) => console.log(`- ${error}`));
  }
}

if (errors.length) {
  process.exit(2);
}

function verifyResult(value) {
  requireString(value.product, 'product');
  requireString(value.version, 'version');
  requireString(value.installer, 'installer');
  requireString(value.artifact_path, 'artifact_path');
  requireString(value.artifact_sha256, 'artifact_sha256');
  requireInteger(value.artifact_size_bytes, 'artifact_size_bytes');
  requireString(value.checked_at, 'checked_at');
  requireString(value.checked_by, 'checked_by');
  requireBoolean(value.app_launched, 'app_launched');
  requireBoolean(value.version_visible, 'version_visible');
  requireBoolean(value.brand_icon_visible, 'brand_icon_visible');
  requireBoolean(value.credential_manager_save_delete_passed, 'credential_manager_save_delete_passed');
  requireBoolean(value.scan_dashboard_loaded, 'scan_dashboard_loaded');
  requireBoolean(value.audit_log_redaction_checked, 'audit_log_redaction_checked');

  if (value.product !== 'Aegis WebShield AI') {
    errors.push('product must be "Aegis WebShield AI".');
  }
  if (typeof value.version === 'string' && !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(value.version)) {
    errors.push('version must be a semantic version string.');
  }
  if (currentVersion && value.version !== currentVersion) {
    errors.push(`version must match current package version ${currentVersion}.`);
  }
  if (typeof value.installer === 'string' && !allowedInstallers.has(value.installer)) {
    errors.push('installer must be one of msi or nsis.');
  }
  verifyArtifact(value);
  if (typeof value.checked_at === 'string' && Number.isNaN(Date.parse(value.checked_at))) {
    errors.push('checked_at must be an ISO-8601 timestamp.');
  }
  for (const field of [
    'app_launched',
    'version_visible',
    'brand_icon_visible',
    'credential_manager_save_delete_passed',
    'scan_dashboard_loaded',
    'audit_log_redaction_checked'
  ]) {
    if (value[field] !== true) {
      errors.push(`${field} must be true for a release candidate.`);
    }
  }
  if (hasBlockedKey(value)) {
    errors.push('app smoke result must not contain API keys, tokens, passwords, customer data, or raw target details.');
  }
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
  } catch (error) {
    errors.push(`Unable to parse app smoke result JSON: ${error.message}`);
    return {};
  }
}

function requireString(value, field) {
  if (typeof value !== 'string' || !value.trim()) {
    errors.push(`${field} is required.`);
  }
}

function requireBoolean(value, field) {
  if (typeof value !== 'boolean') {
    errors.push(`${field} must be a boolean.`);
  }
}

function requireInteger(value, field) {
  if (!Number.isInteger(value)) {
    errors.push(`${field} must be an integer.`);
  }
}

function verifyArtifact(value) {
  if (typeof value.artifact_path !== 'string') {
    return;
  }
  const repoPath = normalizeRepoPath(value.artifact_path);
  if (!isSafeRepoRelativePath(repoPath)) {
    errors.push('artifact_path must be a safe repository-relative path.');
    return;
  }
  if (!isBundleArtifactPath(repoPath)) {
    errors.push('artifact_path must reference a Windows bundle artifact under target/release/bundle or src-tauri/target/release/bundle.');
    return;
  }
  if (currentVersion && !basename(repoPath).includes(`_${currentVersion}_`)) {
    errors.push(`artifact_path filename must match current package version ${currentVersion}.`);
  }

  const artifactPath = resolveRepoPath(repoPath);
  if (!existsSync(artifactPath)) {
    errors.push(`artifact_path does not exist: ${repoPath}`);
    return;
  }

  const stat = statSync(artifactPath);
  if (!stat.isFile()) {
    errors.push(`artifact_path must reference a file: ${repoPath}`);
    return;
  }

  if (value.installer === 'msi' && (!repoPath.toLowerCase().endsWith('.msi') || !repoPath.includes('/msi/'))) {
    errors.push('msi smoke result must reference a .msi artifact under an msi bundle directory.');
  }
  if (value.installer === 'nsis' && (!repoPath.toLowerCase().endsWith('.exe') || !repoPath.includes('/nsis/'))) {
    errors.push('nsis smoke result must reference a .exe artifact under an nsis bundle directory.');
  }

  if (typeof value.artifact_sha256 === 'string' && !/^[a-fA-F0-9]{64}$/.test(value.artifact_sha256)) {
    errors.push('artifact_sha256 must be a 64-character hex SHA-256.');
  } else if (sha256File(artifactPath) !== String(value.artifact_sha256).toLowerCase()) {
    errors.push(`artifact_sha256 does not match current artifact: ${repoPath}`);
  }

  if (Number.isInteger(value.artifact_size_bytes) && value.artifact_size_bytes !== stat.size) {
    errors.push(`artifact_size_bytes does not match current artifact: ${repoPath}`);
  }

  const checkedAt = typeof value.checked_at === 'string' ? Date.parse(value.checked_at) : NaN;
  if (!Number.isNaN(checkedAt) && stat.mtimeMs > checkedAt + 5 * 60 * 1000) {
    errors.push(`checked_at must be after the referenced artifact was generated: ${repoPath}`);
  }
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function hasBlockedKey(value) {
  if (!value || typeof value !== 'object') {
    return false;
  }
  return Object.entries(value).some(([key, nested]) => {
    if (/api[_-]?key|password|token|secret|customer|email|phone|target|url|evidence|prompt/i.test(key)) {
      return true;
    }
    return hasBlockedKey(nested);
  });
}

function valueAfter(name) {
  const index = args.indexOf(name);
  if (index === -1) {
    return null;
  }
  return args[index + 1] ?? null;
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

function isBundleArtifactPath(path) {
  return path.startsWith('target/release/bundle/') || path.startsWith('src-tauri/target/release/bundle/');
}
