import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { basename, join, relative } from 'node:path';

const rootDir = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const packageJson = readJson(join(rootDir, 'package.json'));
const tauriConfig = readJson(join(rootDir, 'src-tauri', 'tauri.conf.json'));
const cargoToml = readFileSync(join(rootDir, 'src-tauri', 'Cargo.toml'), 'utf8');
const cargoVersion = cargoToml.match(/^version\s*=\s*"([^"]+)"/m)?.[1];

const versions = {
  package: packageJson.version,
  tauri: tauriConfig.version,
  cargo: cargoVersion
};
const uniqueVersions = new Set(Object.values(versions));
if (uniqueVersions.size !== 1) {
  throw new Error(`Version mismatch: ${JSON.stringify(versions)}`);
}

const version = packageJson.version;
const releaseDir = join(rootDir, 'release');
mkdirSync(releaseDir, { recursive: true });

const bundleDir = resolveBundleDir();
const artifacts = existsSync(bundleDir) ? listFiles(bundleDir).filter(isCurrentVersionArtifact) : [];
const ruleFeedArtifacts = prepareRuleFeedArtifacts(releaseDir, version);
const releaseArtifacts = [...artifacts, ...ruleFeedArtifacts.files];
const checksumLines = releaseArtifacts.map((artifact) => {
  const hash = createHash('sha256').update(readFileSync(artifact)).digest('hex');
  return `${hash}  ${relative(rootDir, artifact).replaceAll('\\', '/')}`;
});

if (checksumLines.length > 0) {
  writeFileSync(join(releaseDir, `SHA256SUMS-${version}.txt`), `${checksumLines.join('\n')}\n`, 'utf8');
}

const gitLines = gitLog();
const knownIssues = releaseListFromEnv(
  'AEGIS_RELEASE_KNOWN_ISSUES',
  [
    'Publishing is blocked until every MSI/NSIS artifact has valid Authenticode signature evidence.',
    'Installed-app UI, Credential Manager, dashboard, and audit-redaction smoke evidence must be recorded for the current installer artifact.',
    'The update manifest requires the real public HTTPS artifact URL and release signature for the current version.',
    'A redacted support diagnostics artifact from the release candidate must pass support diagnostics verification.'
  ]
);
const upgradeNotes = releaseListFromEnv(
  'AEGIS_RELEASE_UPGRADE_NOTES',
  ['No automated data migration steps are required for this release.']
);
const notes = [
  `# Aegis WebShield AI ${version}`,
  '',
  `Generated: ${new Date().toISOString()}`,
  '',
  '## Release Checks',
  '',
  '- Run `npm run verify:windows` on Windows PowerShell.',
  '- Run `npm run rc:security-performance` and `npm run rc:functional-e2e` from the exact clean release commit.',
  '- Run `npm run bundle:windows` before publishing installer artifacts.',
  '- Run `npm run smoke:windows-installer` after bundling artifacts.',
  '- Verify Authenticode signatures and separate MSI/NSIS installed-app smoke evidence against current artifact SHA-256 and size.',
  '- Verify the public update manifest and redacted support diagnostics evidence.',
  '- Run `npm run release:prepare` with signed rule feed environment variables when publishing rule updates.',
  '- Run `npm run release:audit -- --strict` and do not publish while any required check fails.',
  '- Confirm API keys and finding evidence are not written to audit metadata.',
  '- Confirm scans are limited to explicitly approved targets.',
  ...(ruleFeedArtifacts.summary.length ? ruleFeedArtifacts.summary : ['- No rule pack update feed was provided.']),
  '',
  '## Known Issues',
  '',
  ...knownIssues.map((issue) => `- ${issue}`),
  '',
  '## Upgrade Notes',
  '',
  ...upgradeNotes.map((note) => `- ${note}`),
  '',
  '## Recent Changes',
  '',
  ...gitLines.map((line) => `- ${line}`),
  '',
  '## Artifacts',
  '',
  ...(artifacts.length
    ? artifacts.map((artifact) => `- ${relative(rootDir, artifact).replaceAll('\\', '/')}`)
    : ['- No bundle artifacts found yet. Run `npm run bundle:windows` on Windows.']),
  ...ruleFeedArtifacts.files.map((artifact) => `- ${relative(rootDir, artifact).replaceAll('\\', '/')}`),
  ''
].join('\n');

writeFileSync(join(releaseDir, `Aegis-WebShield-AI-${version}.md`), notes, 'utf8');
console.log(`Prepared release notes for ${version}`);
console.log(`Artifacts indexed: ${releaseArtifacts.length}`);
if (ruleFeedArtifacts.summary.length) {
  console.log('Rule feed prepared');
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function listFiles(dir) {
  return readdirSync(dir)
    .flatMap((entry) => {
      const path = join(dir, entry);
      const stat = statSync(path);
      return stat.isDirectory() ? listFiles(path) : [path];
    })
    .filter((path) => /\.(exe|msi|zip|msix|appx|dmg|deb|rpm)$/i.test(path));
}

function resolveBundleDir() {
  const candidates = [
    join(rootDir, 'target', 'release', 'bundle'),
    join(rootDir, 'src-tauri', 'target', 'release', 'bundle')
  ];
  return candidates.find((path) => existsSync(path)) ?? candidates[0];
}

function isCurrentVersionArtifact(path) {
  return basename(path).includes(`_${version}_`);
}

function gitLog() {
  try {
    return execFileSync('git', ['log', '--max-count=20', '--pretty=format:%h %s'], {
      cwd: rootDir,
      encoding: 'utf8'
    })
      .split('\n')
      .filter(Boolean);
  } catch {
    return ['Git history unavailable'];
  }
}

function releaseListFromEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  const values = raw
    .split(/\r?\n|;/)
    .map((value) => value.trim())
    .filter(Boolean);
  return values.length ? values : fallback;
}

function prepareRuleFeedArtifacts(releaseDir, version) {
  const feedPath = process.env.AEGIS_RULE_FEED_PATH;
  if (!feedPath) {
    const existingFiles = [
      join(releaseDir, `rule-feed-${version}.signed.json`),
      join(releaseDir, `rule-feed-sign-${version}.json`),
      join(releaseDir, `rule-feed-check-${version}.json`)
    ].filter((path) => existsSync(path));
    return {
      files: existingFiles,
      summary: existingFiles.length
        ? ['- Existing rule pack release artifacts were indexed for checksum verification.']
        : []
    };
  }
  if (!isSafeRepoRelativePath(normalizeRepoPath(feedPath))) {
    throw new Error('AEGIS_RULE_FEED_PATH must be a safe repository-relative path.');
  }
  const resolvedFeedPath = resolveRepoPath(feedPath);
  if (!existsSync(resolvedFeedPath)) {
    throw new Error(`Rule feed file not found: ${feedPath}`);
  }

  const privateKeyHex = process.env.AEGIS_RULE_FEED_PRIVATE_KEY_HEX;
  const explicitPublicKeyHex = process.env.AEGIS_RULE_FEED_PUBLIC_KEY_HEX;
  const currentVersion = process.env.AEGIS_RULE_FEED_CURRENT_VERSION;
  const files = [];
  const summary = [];
  let feedToCheck = resolvedFeedPath;
  let publicKeyHex = explicitPublicKeyHex;

  if (privateKeyHex) {
    const signedFeedPath = join(releaseDir, `rule-feed-${version}.signed.json`);
    const signReport = runAegisScanJson([
      'rules',
      'feed-sign',
      '--file',
      resolvedFeedPath,
      '--private-key-hex',
      privateKeyHex,
      '--out',
      signedFeedPath,
      '--format',
      'json'
    ]);
    const signReportPath = join(releaseDir, `rule-feed-sign-${version}.json`);
    writeFileSync(signReportPath, `${JSON.stringify(signReport, null, 2)}\n`, 'utf8');
    files.push(signedFeedPath, signReportPath);
    feedToCheck = signedFeedPath;
    publicKeyHex = signReport.public_key_hex;
    summary.push('- Rule pack update feed was signed for release.');
  }

  const checkArgs = ['rules', 'feed-check', '--file', feedToCheck, '--format', 'json'];
  if (currentVersion) {
    checkArgs.push('--current-version', currentVersion);
  }
  if (publicKeyHex) {
    checkArgs.push('--public-key-hex', publicKeyHex);
  }
  const checkReport = runAegisScanJson(checkArgs);
  const checkReportPath = join(releaseDir, `rule-feed-check-${version}.json`);
  writeFileSync(checkReportPath, `${JSON.stringify(checkReport, null, 2)}\n`, 'utf8');
  files.push(checkReportPath);
  summary.push(`- Rule pack feed check passed for channel \`${checkReport.channel}\`.`);
  if (checkReport.signature_verified) {
    summary.push('- Rule pack feed signature was verified.');
  }
  return { files, summary };
}

function runAegisScanJson(args) {
  const childEnv = { ...process.env };
  delete childEnv.AEGIS_RULE_FEED_PRIVATE_KEY_HEX;
  const output = execFileSync('cargo', ['run', '--quiet', '-p', 'aegis-cli', '--bin', 'aegis-scan', '--', ...args], {
    cwd: rootDir,
    encoding: 'utf8',
    env: childEnv
  });
  return JSON.parse(output);
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
