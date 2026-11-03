import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const jsonOutput = args.includes('--json');
const manifestArg = valueAfter('--file');
const errors = [];
const warnings = [];
const packageJson = readJson(join(rootDir, 'package.json'));
const currentVersion = typeof packageJson.version === 'string' ? packageJson.version : null;

if (!manifestArg) {
  errors.push('Missing required --file <path> argument.');
} else if (!isSafeRepoRelativePath(normalizeRepoPath(manifestArg))) {
  errors.push('--file must be a safe repository-relative path.');
}

const manifestPath = manifestArg && isSafeRepoRelativePath(normalizeRepoPath(manifestArg)) ? resolveRepoPath(manifestArg) : null;
let manifest = {};
if (manifestPath && !existsSync(manifestPath)) {
  errors.push(`Update manifest not found: ${manifestArg}`);
} else if (manifestPath) {
  manifest = readJson(manifestPath);
}

if (!errors.length) {
  verifyManifest(manifest);
}

const summary = {
  passed: errors.length === 0,
  manifest: manifestArg ?? null,
  channel: typeof manifest.channel === 'string' ? manifest.channel : null,
  version: typeof manifest.version === 'string' ? manifest.version : null,
  platform_count: manifest.platforms && typeof manifest.platforms === 'object' ? Object.keys(manifest.platforms).length : 0,
  warning_count: warnings.length,
  error_count: errors.length,
  warnings,
  errors
};

if (jsonOutput) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.log(`Update manifest verification: ${summary.passed ? 'passed' : 'failed'}`);
  if (summary.channel) {
    console.log(`Channel: ${summary.channel}`);
  }
  if (summary.version) {
    console.log(`Version: ${summary.version}`);
  }
  console.log(`Platforms: ${summary.platform_count}`);
  if (warnings.length) {
    console.log('\nWarnings:');
    warnings.forEach((warning) => console.log(`- ${warning}`));
  }
  if (errors.length) {
    console.log('\nErrors:');
    errors.forEach((error) => console.log(`- ${error}`));
  }
}

if (errors.length) {
  process.exit(2);
}

function verifyManifest(value) {
  requireString(value.product, 'product');
  requireString(value.version, 'version');
  requireString(value.channel, 'channel');
  requireString(value.pub_date, 'pub_date');

  if (value.product !== 'Aegis WebShield AI') {
    errors.push('product must be "Aegis WebShield AI".');
  }
  if (typeof value.version === 'string' && !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(value.version)) {
    errors.push('version must be a semantic version string.');
  }
  if (currentVersion && value.version !== currentVersion) {
    errors.push(`version must match current package version ${currentVersion}.`);
  }
  if (typeof value.channel === 'string' && !['stable', 'beta', 'internal'].includes(value.channel)) {
    errors.push('channel must be one of stable, beta, or internal.');
  }
  if (typeof value.pub_date === 'string' && Number.isNaN(Date.parse(value.pub_date))) {
    errors.push('pub_date must be an ISO-8601 timestamp.');
  }
  if (hasBlockedKey(value)) {
    errors.push('manifest must not contain private keys, tokens, API keys, or passwords.');
  }

  if (!value.platforms || typeof value.platforms !== 'object' || Array.isArray(value.platforms)) {
    errors.push('platforms must be an object keyed by platform id.');
    return;
  }

  const platforms = Object.entries(value.platforms);
  if (!platforms.length) {
    errors.push('platforms must include at least one platform artifact.');
  }
  if (!value.platforms['windows-x86_64']) {
    errors.push('platforms must include windows-x86_64 for the Windows desktop release.');
  }

  for (const [platform, artifact] of platforms) {
    verifyPlatform(platform, artifact);
  }
}

function verifyPlatform(platform, artifact) {
  if (!/^[a-z0-9_-]+(?:-[a-z0-9_]+)*$/.test(platform)) {
    errors.push(`Invalid platform id: ${platform}`);
  }
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
    errors.push(`Platform ${platform} must be an object.`);
    return;
  }

  requireString(artifact.url, `platforms.${platform}.url`);
  requireString(artifact.sha256, `platforms.${platform}.sha256`);
  requireString(artifact.signature, `platforms.${platform}.signature`);
  if (typeof artifact.url === 'string') {
    verifyArtifactUrl(platform, artifact.url);
  }
  if (typeof artifact.sha256 === 'string' && !/^[a-fA-F0-9]{64}$/.test(artifact.sha256)) {
    errors.push(`platforms.${platform}.sha256 must be a 64-character hex SHA-256.`);
  }
  if (typeof artifact.signature === 'string' && artifact.signature.trim().length < 32) {
    errors.push(`platforms.${platform}.signature is too short to be a release signature.`);
  }
  if (artifact.size_bytes !== undefined && (!Number.isInteger(artifact.size_bytes) || artifact.size_bytes <= 0)) {
    errors.push(`platforms.${platform}.size_bytes must be a positive integer when provided.`);
  }
}

function verifyArtifactUrl(platform, value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    errors.push(`platforms.${platform}.url must be a valid URL.`);
    return;
  }
  if (parsed.protocol !== 'https:') {
    errors.push(`platforms.${platform}.url must use https.`);
  }
  if (parsed.username || parsed.password) {
    errors.push(`platforms.${platform}.url must not include embedded credentials.`);
  }
  if (parsed.search || parsed.hash) {
    errors.push(`platforms.${platform}.url must not include query strings or fragments.`);
  }
  if (/api[_-]?key|password|token|secret/i.test(value)) {
    errors.push(`platforms.${platform}.url must not contain sensitive labels.`);
  }
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
  } catch (error) {
    errors.push(`Unable to parse update manifest JSON: ${error.message}`);
    return {};
  }
}

function requireString(value, field) {
  if (typeof value !== 'string' || !value.trim()) {
    errors.push(`${field} is required.`);
  }
}

function hasBlockedKey(value) {
  if (!value || typeof value !== 'object') {
    return false;
  }
  return Object.entries(value).some(([key, nested]) => {
    if (/private|password|token|api[_-]?key|secret/i.test(key)) {
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
