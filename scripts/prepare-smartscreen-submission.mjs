import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const packageJson = readJson(join(rootDir, 'package.json'));
const version = packageJson.version;
const releaseDir = join(rootDir, 'release');
const outputDir = join(releaseDir, 'smartscreen');
const bundleDir = resolveBundleDir();
const jsonOutput = process.argv.includes('--json');
mkdirSync(outputDir, { recursive: true });

const artifacts = existsSync(bundleDir)
  ? listFiles(bundleDir).filter((path) => /\.(msi|exe)$/i.test(path) && isCurrentVersionArtifact(path))
  : [];
const checksumPath = join(releaseDir, `SHA256SUMS-${version}.txt`);
const releaseNotesPath = join(releaseDir, `Aegis-WebShield-AI-${version}.md`);
const signatureReportPath = join(releaseDir, 'signature-verification.json');
const updateManifestPath = process.env.AEGIS_UPDATE_MANIFEST_PATH
  ? resolveReleaseInput(process.env.AEGIS_UPDATE_MANIFEST_PATH)
  : null;

const artifactSummaries = artifacts.map((artifact) => ({
  path: toRepoPath(artifact),
  size_bytes: statSync(artifact).size,
  sha256: sha256File(artifact)
}));
const currentSignatureReportPath = artifactEvidenceMatches(signatureReportPath, artifactSummaries)
  ? signatureReportPath
  : null;
const installerSmokeReport = latestArtifactEvidenceFile(
  join(releaseDir, 'installer-smoke'),
  /^installer-smoke-.+\.json$/,
  artifactSummaries
);

const checklist = [];
addChecklist('Release notes generated', existsSync(releaseNotesPath), toRepoPath(releaseNotesPath));
addChecklist('Checksums generated', existsSync(checksumPath), toRepoPath(checksumPath));
addChecklist('Installer artifacts present', artifacts.length > 0, `${artifacts.length} artifact(s)`);
addChecklist(
  'Signature verification report attached',
  Boolean(currentSignatureReportPath),
  currentSignatureReportPath ? toRepoPath(currentSignatureReportPath) : 'missing or stale for current artifacts'
);
addChecklist('Installer smoke report attached', Boolean(installerSmokeReport), installerSmokeReport ? toRepoPath(installerSmokeReport) : null);
if (updateManifestPath) {
  addChecklist('Update manifest attached', existsSync(updateManifestPath), toRepoPath(updateManifestPath));
}

const packageSummary = {
  generated_at: new Date().toISOString(),
  product: 'Aegis WebShield AI',
  version,
  purpose: 'Windows Defender SmartScreen reputation review submission evidence',
  checklist,
  artifacts: artifactSummaries,
  evidence_files: evidenceFiles(),
  notes: [
    'Submit only signed release artifacts.',
    'Do not include API keys, license secrets, private signing keys, customer data, scan evidence, or local database files.',
    'Keep Microsoft submission case IDs in the release tracker, not in public release notes.'
  ]
};

const jsonPath = join(outputDir, `smartscreen-submission-${version}.json`);
const markdownPath = join(outputDir, `smartscreen-submission-${version}.md`);
writeFileSync(jsonPath, `${JSON.stringify(packageSummary, null, 2)}\n`, 'utf8');
writeFileSync(markdownPath, renderMarkdown(packageSummary), 'utf8');

if (jsonOutput) {
  console.log(JSON.stringify(packageSummary, null, 2));
} else {
  console.log(`Prepared SmartScreen submission package for ${version}`);
  console.log(`Artifacts indexed: ${artifactSummaries.length}`);
  console.log(`JSON: ${toRepoPath(jsonPath)}`);
  console.log(`Markdown: ${toRepoPath(markdownPath)}`);
}

function addChecklist(label, passed, detail) {
  checklist.push({
    label,
    passed,
    detail
  });
}

function isCurrentVersionArtifact(path) {
  return basename(path).includes(`_${version}_`);
}

function evidenceFiles() {
  const files = [
    releaseNotesPath,
    checksumPath,
    currentSignatureReportPath,
    installerSmokeReport,
    updateManifestPath
  ].filter(Boolean);
  return files.map((path) => ({
    path: toRepoPath(path),
    present: existsSync(path)
  }));
}

function renderMarkdown(summary) {
  return [
    `# SmartScreen Submission Package - ${summary.product} ${summary.version}`,
    '',
    `Generated: ${summary.generated_at}`,
    '',
    '## Checklist',
    '',
    ...summary.checklist.map((item) => `- [${item.passed ? 'x' : ' '}] ${item.label}${item.detail ? `: ${item.detail}` : ''}`),
    '',
    '## Artifacts',
    '',
    ...(summary.artifacts.length
      ? summary.artifacts.map((artifact) => `- ${artifact.path} (${artifact.size_bytes} bytes, sha256 ${artifact.sha256})`)
      : ['- No MSI/NSIS artifacts found. Run `npm run bundle:windows` and sign artifacts before submission.']),
    '',
    '## Evidence Files',
    '',
    ...summary.evidence_files.map((file) => `- [${file.present ? 'x' : ' '}] ${file.path}`),
    '',
    '## Submission Notes',
    '',
    ...summary.notes.map((note) => `- ${note}`),
    ''
  ].join('\n');
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
  return latestFiles(dir, pattern)
    .find((path) => artifactEvidenceMatches(path, expectedArtifacts)) ?? null;
}

function latestFiles(dir, pattern) {
  if (!existsSync(dir)) {
    return [];
  }
  return readdirSync(dir)
    .map((entry) => join(dir, entry))
    .filter((path) => statSync(path).isFile() && pattern.test(path.split(/[\\/]/).pop() ?? ''))
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
}

function artifactEvidenceMatches(path, expectedArtifacts) {
  if (!path || !existsSync(path) || expectedArtifacts.length === 0) {
    return false;
  }
  let report;
  try {
    report = JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
  } catch {
    return false;
  }
  if (!Array.isArray(report.artifacts) || report.artifacts.length !== expectedArtifacts.length) {
    return false;
  }
  const byPath = new Map(report.artifacts.map((artifact) => [normalizeRepoPath(artifact?.path ?? ''), artifact]));
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

function resolveReleaseInput(path) {
  const repoPath = normalizeRepoPath(path);
  if (!isSafeRepoPath(repoPath)) {
    throw new Error(`Update manifest path must be a safe repo-relative path: ${path}`);
  }
  return join(rootDir, ...repoPath.split('/'));
}

function toRepoPath(path) {
  return relative(rootDir, path).replaceAll('\\', '/');
}

function normalizeRepoPath(path) {
  return path.replaceAll('\\', '/');
}

function isSafeRepoPath(path) {
  if (!path || path.startsWith('/') || /^[A-Za-z]:/.test(path)) {
    return false;
  }
  return path
    .split('/')
    .every((segment) => segment && segment !== '.' && segment !== '..');
}
