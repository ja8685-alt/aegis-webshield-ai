import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const trackerArg = valueAfter('--file');
const jsonOutput = args.includes('--json');
const errors = [];
const allowedStatuses = new Set(['submitted', 'under_review', 'approved', 'needs_changes', 'rejected', 'closed']);
const allowedChannels = new Set(['stable', 'beta', 'internal']);
const packageJson = readJson(join(rootDir, 'package.json'));
const currentVersion = typeof packageJson.version === 'string' ? packageJson.version : null;
const bundleDir = resolveBundleDir();
const bundleArtifacts = existsSync(bundleDir)
  ? listFiles(bundleDir).filter((path) => /\.(msi|exe)$/i.test(path) && isCurrentVersionArtifact(path))
  : [];
const bundleArtifactSummaries = bundleArtifacts.map((artifact) => ({
  path: toRepoPath(artifact),
  sha256: sha256File(artifact)
}));

if (!trackerArg) {
  errors.push('Missing required --file <path> argument.');
} else if (!isSafeArtifactRepoPath(normalizeRepoPath(trackerArg))) {
  errors.push('--file must be a safe repository-relative path.');
}

const trackerPath = trackerArg && isSafeArtifactRepoPath(normalizeRepoPath(trackerArg)) ? resolveRepoPath(trackerArg) : null;
let tracker = {};
if (trackerPath && !existsSync(trackerPath)) {
  errors.push(`SmartScreen tracker not found: ${trackerArg}`);
} else if (trackerPath) {
  tracker = readJson(trackerPath);
}

if (!errors.length) {
  verifyTracker(tracker);
}

const summary = {
  passed: errors.length === 0,
  tracker: trackerArg ?? null,
  version: typeof tracker.version === 'string' ? tracker.version : null,
  channel: typeof tracker.channel === 'string' ? tracker.channel : null,
  status: typeof tracker.status === 'string' ? tracker.status : null,
  error_count: errors.length,
  errors
};

if (jsonOutput) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.log(`SmartScreen tracker verification: ${summary.passed ? 'passed' : 'failed'}`);
  if (summary.version) {
    console.log(`Version: ${summary.version}`);
  }
  if (summary.channel) {
    console.log(`Channel: ${summary.channel}`);
  }
  if (summary.status) {
    console.log(`Status: ${summary.status}`);
  }
  if (errors.length) {
    console.log('\nErrors:');
    errors.forEach((error) => console.log(`- ${error}`));
  }
}

if (errors.length) {
  process.exit(2);
}

function verifyTracker(value) {
  requireString(value.product, 'product');
  requireString(value.version, 'version');
  requireString(value.channel, 'channel');
  requireString(value.submission_case_id, 'submission_case_id');
  requireString(value.submitted_at, 'submitted_at');
  requireString(value.status, 'status');
  requireString(value.next_review_at, 'next_review_at');
  requireArray(value.artifacts, 'artifacts');

  if (value.product !== 'Aegis WebShield AI') {
    errors.push('product must be "Aegis WebShield AI".');
  }
  if (typeof value.version === 'string' && !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(value.version)) {
    errors.push('version must be a semantic version string.');
  }
  if (currentVersion && value.version !== currentVersion) {
    errors.push(`version must match current package version ${currentVersion}.`);
  }
  if (typeof value.channel === 'string' && !allowedChannels.has(value.channel)) {
    errors.push('channel must be one of stable, beta, or internal.');
  }
  if (typeof value.status === 'string' && !allowedStatuses.has(value.status)) {
    errors.push(`status must be one of ${Array.from(allowedStatuses).join(', ')}.`);
  }
  verifyCaseId(value.submission_case_id);
  verifyDate(value.submitted_at, 'submitted_at');
  verifyDate(value.next_review_at, 'next_review_at');
  verifyReviewWindow(value.submitted_at, value.next_review_at);
  if (hasBlockedKey(value)) {
    errors.push('tracker must not contain private keys, tokens, API keys, passwords, customer data, or account identifiers.');
  }
  if (Array.isArray(value.artifacts)) {
    const artifactPaths = new Set();
    for (const [index, artifact] of value.artifacts.entries()) {
      verifyArtifact(artifact, index);
      if (artifact && typeof artifact.path === 'string') {
        artifactPaths.add(normalizeRepoPath(artifact.path));
      }
    }
    for (const artifact of bundleArtifactSummaries) {
      if (!artifactPaths.has(artifact.path)) {
        errors.push(`artifacts must include current bundle artifact: ${artifact.path}`);
      }
    }
  }
}

function verifyCaseId(value) {
  if (typeof value !== 'string') {
    return;
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{5,79}$/.test(value)) {
    errors.push('submission_case_id must be a 6-80 character Microsoft case identifier without whitespace.');
  }
}

function verifyReviewWindow(submittedAt, nextReviewAt) {
  if (typeof submittedAt !== 'string' || typeof nextReviewAt !== 'string') {
    return;
  }
  const submitted = Date.parse(submittedAt);
  const nextReview = Date.parse(nextReviewAt);
  if (!Number.isNaN(submitted) && !Number.isNaN(nextReview) && nextReview < submitted) {
    errors.push('next_review_at must be the same as or later than submitted_at.');
  }
}

function verifyArtifact(artifact, index) {
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
    errors.push(`artifacts[${index}] must be an object.`);
    return;
  }
  requireString(artifact.path, `artifacts[${index}].path`);
  requireString(artifact.sha256, `artifacts[${index}].sha256`);
  if (typeof artifact.sha256 === 'string' && !/^[a-fA-F0-9]{64}$/.test(artifact.sha256)) {
    errors.push(`artifacts[${index}].sha256 must be a 64-character hex SHA-256.`);
  }
  if (typeof artifact.path === 'string') {
    const repoPath = normalizeRepoPath(artifact.path);
    if (!isSafeArtifactRepoPath(repoPath)) {
      errors.push(`artifacts[${index}].path must be a safe repo-relative path.`);
      return;
    }
    const artifactPath = join(rootDir, ...repoPath.split('/'));
    if (!existsSync(artifactPath)) {
      errors.push(`artifacts[${index}].path does not exist: ${repoPath}`);
      return;
    }
    if (typeof artifact.sha256 === 'string' && /^[a-fA-F0-9]{64}$/.test(artifact.sha256)) {
      const actualHash = sha256File(artifactPath);
      if (actualHash !== artifact.sha256.toLowerCase()) {
        errors.push(`artifacts[${index}].sha256 does not match ${repoPath}.`);
      }
      const currentBundleArtifact = bundleArtifactSummaries.find((artifact) => artifact.path === repoPath);
      if (currentBundleArtifact && currentBundleArtifact.sha256 !== artifact.sha256.toLowerCase()) {
        errors.push(`artifacts[${index}].sha256 does not match current bundle artifact: ${repoPath}.`);
      }
    }
  }
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
  } catch (error) {
    errors.push(`Unable to parse SmartScreen tracker JSON: ${error.message}`);
    return {};
  }
}

function requireString(value, field) {
  if (typeof value !== 'string' || !value.trim()) {
    errors.push(`${field} is required.`);
  }
}

function requireArray(value, field) {
  if (!Array.isArray(value) || !value.length) {
    errors.push(`${field} must be a non-empty array.`);
  }
}

function verifyDate(value, field) {
  if (typeof value === 'string' && Number.isNaN(Date.parse(value))) {
    errors.push(`${field} must be an ISO-8601 timestamp.`);
  }
}

function hasBlockedKey(value) {
  if (!value || typeof value !== 'object') {
    return false;
  }
  return Object.entries(value).some(([key, nested]) => {
    if (/private|password|token|api[_-]?key|secret|customer|account|email|phone/i.test(key)) {
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

function normalizeRepoPath(path) {
  return path.replaceAll('\\', '/');
}

function resolveRepoPath(path) {
  return join(rootDir, ...normalizeRepoPath(path).split('/'));
}

function toRepoPath(path) {
  return path.replace(rootDir, '').replace(/^[/\\]/, '').replaceAll('\\', '/');
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

function isCurrentVersionArtifact(path) {
  return currentVersion ? basename(path).includes(`_${currentVersion}_`) : false;
}

function isSafeArtifactRepoPath(path) {
  if (!path || path.startsWith('/') || /^[A-Za-z]:/.test(path)) {
    return false;
  }
  return path
    .split('/')
    .every((segment) => segment && segment !== '.' && segment !== '..');
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}
