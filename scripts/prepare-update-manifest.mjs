import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const jsonOutput = args.includes('--json');
const dryRun = args.includes('--dry-run');
const packageJson = readJson(join(rootDir, 'package.json'));
const version = valueAfter('--version') ?? packageJson.version;
const channel = valueAfter('--channel') ?? 'stable';
const platform = valueAfter('--platform') ?? 'windows-x86_64';
const artifactKind = valueAfter('--artifact') ?? 'nsis';
const artifactUrl = valueAfter('--artifact-url');
const baseUrl = valueAfter('--base-url') ?? process.env.AEGIS_UPDATE_BASE_URL;
const signature = valueAfter('--signature') ?? process.env.AEGIS_RELEASE_SIGNATURE;
const pubDate = valueAfter('--pub-date') ?? new Date().toISOString();
const outArg = valueAfter('--out') ?? `release/update-manifest-${version}.json`;
const errors = [];

if (!['stable', 'beta', 'internal'].includes(channel)) {
  errors.push('--channel must be stable, beta, or internal.');
}
if (!['msi', 'nsis'].includes(artifactKind)) {
  errors.push('--artifact must be msi or nsis.');
}
if (version !== packageJson.version) {
  errors.push(`--version must match current package version ${packageJson.version}.`);
}
if (platform !== 'windows-x86_64') {
  errors.push('--platform must be windows-x86_64 for the Windows desktop release.');
}
if (!signature || signature.trim().length < 32) {
  errors.push('Missing required release signature. Pass --signature or set AEGIS_RELEASE_SIGNATURE.');
}
if (hasSensitiveText(signature)) {
  errors.push('Release signature must not include private key, token, password, or API key labels.');
}
if (outArg && !isSafeRepoRelativePath(normalizeRepoPath(outArg))) {
  errors.push('--out must be a safe repository-relative path.');
}

const artifact = selectArtifact(artifactKind);
if (!artifact) {
  errors.push(`No ${artifactKind} artifact found under ${toRepoPath(resolveBundleDir())}. Run npm run bundle:windows first.`);
}

const url = artifact ? resolveArtifactUrl(artifact, artifactUrl, baseUrl) : null;
if (url) {
  verifyArtifactUrl('artifact URL', url);
}

let manifest = null;
if (!errors.length) {
  manifest = {
    product: 'Aegis WebShield AI',
    version,
    channel,
    pub_date: pubDate,
    platforms: {
      [platform]: {
        url,
        sha256: sha256File(artifact),
        signature: signature.trim(),
        size_bytes: statSync(artifact).size
      }
    }
  };

  verifyPreparedManifest(manifest);
}

const outPath = outArg ? resolveRepoPath(outArg) : null;
if (!errors.length && !dryRun) {
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}

const summary = {
  passed: errors.length === 0,
  dry_run: dryRun,
  manifest: !errors.length && !dryRun ? toRepoPath(outPath) : null,
  artifact: artifact ? toRepoPath(artifact) : null,
  artifact_url: url,
  version,
  channel,
  platform,
  error_count: errors.length,
  errors
};

if (jsonOutput) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.log(`Update manifest preparation: ${summary.passed ? 'passed' : 'failed'}`);
  if (summary.manifest) {
    console.log(`Manifest: ${summary.manifest}`);
  }
  if (summary.artifact) {
    console.log(`Artifact: ${summary.artifact}`);
  }
  if (errors.length) {
    console.log('\nErrors:');
    errors.forEach((error) => console.log(`- ${error}`));
  }
}

if (errors.length) {
  process.exit(2);
}

function selectArtifact(kind) {
  const bundleDir = resolveBundleDir();
  if (!existsSync(bundleDir)) {
    return null;
  }
  const extension = kind === 'msi' ? '.msi' : '.exe';
  const marker = kind === 'msi' ? '/msi/' : '/nsis/';
  return listFiles(bundleDir)
    .filter((path) => normalizeRepoPath(path).includes(marker)
      && path.toLowerCase().endsWith(extension)
      && basename(path).includes(`_${version}_`))
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0] ?? null;
}

function resolveArtifactUrl(artifactPath, explicitUrl, releaseBaseUrl) {
  if (explicitUrl) {
    return explicitUrl.trim();
  }
  if (!releaseBaseUrl) {
    errors.push('Missing artifact URL. Pass --artifact-url or set --base-url/AEGIS_UPDATE_BASE_URL.');
    return null;
  }

  const base = releaseBaseUrl.endsWith('/') ? releaseBaseUrl : `${releaseBaseUrl}/`;
  return new URL(encodeURIComponent(basename(artifactPath)), base).toString();
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

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function valueAfter(name) {
  const index = args.indexOf(name);
  if (index === -1) {
    return null;
  }
  return args[index + 1] ?? null;
}

function toRepoPath(path) {
  return relative(rootDir, path).replaceAll('\\', '/');
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

function hasSensitiveText(value) {
  return /private[_ -]?key|password|token|api[_ -]?key|secret/i.test(String(value));
}

function verifyPreparedManifest(value) {
  if (value.product !== 'Aegis WebShield AI') {
    errors.push('product must be "Aegis WebShield AI".');
  }
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(value.version)) {
    errors.push('version must be a semantic version string.');
  }
  if (value.version !== packageJson.version) {
    errors.push(`version must match current package version ${packageJson.version}.`);
  }
  if (!['stable', 'beta', 'internal'].includes(value.channel)) {
    errors.push('channel must be one of stable, beta, or internal.');
  }
  if (Number.isNaN(Date.parse(value.pub_date))) {
    errors.push('pub_date must be an ISO-8601 timestamp.');
  }
  if (!value.platforms || typeof value.platforms !== 'object' || Array.isArray(value.platforms)) {
    errors.push('platforms must be an object keyed by platform id.');
    return;
  }
  if (!value.platforms['windows-x86_64']) {
    errors.push('platforms must include windows-x86_64 for the Windows desktop release.');
  }
  for (const [platformName, artifact] of Object.entries(value.platforms)) {
    if (!/^[a-z0-9_-]+(?:-[a-z0-9_]+)*$/.test(platformName)) {
      errors.push(`Invalid platform id: ${platformName}`);
    }
    if (typeof artifact.url === 'string') {
      verifyArtifactUrl(`platforms.${platformName}.url`, artifact.url);
    }
    if (!/^[a-fA-F0-9]{64}$/.test(artifact.sha256)) {
      errors.push(`platforms.${platformName}.sha256 must be a 64-character hex SHA-256.`);
    }
    if (artifact.signature.trim().length < 32) {
      errors.push(`platforms.${platformName}.signature is too short to be a release signature.`);
    }
    if (!Number.isInteger(artifact.size_bytes) || artifact.size_bytes <= 0) {
      errors.push(`platforms.${platformName}.size_bytes must be a positive integer.`);
    }
  }
}

function verifyArtifactUrl(label, value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    errors.push(`${label} must be a valid URL.`);
    return;
  }
  if (parsed.protocol !== 'https:') {
    errors.push(`${label} must use https.`);
  }
  if (parsed.username || parsed.password) {
    errors.push(`${label} must not include embedded credentials.`);
  }
  if (parsed.search || parsed.hash) {
    errors.push(`${label} must not include query strings or fragments.`);
  }
  if (/api[_-]?key|password|token|secret/i.test(value)) {
    errors.push(`${label} must not contain sensitive labels.`);
  }
}
