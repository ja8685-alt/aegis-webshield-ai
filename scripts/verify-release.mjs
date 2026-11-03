import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const errors = [];
const warnings = [];
const checkedFiles = [];
const checksumEntries = new Set();

const packageJson = readJson(join(rootDir, 'package.json'));
const tauriConfig = readJson(join(rootDir, 'src-tauri', 'tauri.conf.json'));
const cargoToml = readFileSync(join(rootDir, 'src-tauri', 'Cargo.toml'), 'utf8');
const cargoVersion = cargoToml.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
const version = packageJson.version;
const releaseDir = join(rootDir, 'release');
const jsonOutput = process.argv.includes('--json');

verifyVersionConsistency();
verifyRequiredReleaseNotes();
verifyChecksums();
verifyRuleFeedArtifacts();
verifySmartScreenPackage();

const summary = {
  version,
  passed: errors.length === 0,
  checked_files: checkedFiles.length,
  warning_count: warnings.length,
  error_count: errors.length,
  warnings,
  errors
};

if (jsonOutput) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.log(`Release verification for ${version}: ${summary.passed ? 'passed' : 'failed'}`);
  console.log(`Checked files: ${summary.checked_files}`);
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

function verifyVersionConsistency() {
  const versions = {
    package: packageJson.version,
    tauri: tauriConfig.version,
    cargo: cargoVersion
  };
  if (new Set(Object.values(versions)).size !== 1) {
    errors.push(`Version mismatch: ${JSON.stringify(versions)}`);
  }
}

function verifyRequiredReleaseNotes() {
  const notesPath = join(releaseDir, `Aegis-WebShield-AI-${version}.md`);
  if (!existsSync(notesPath)) {
    errors.push(`Missing release notes: ${toRepoPath(notesPath)}`);
    return;
  }
  checkedFiles.push(toRepoPath(notesPath));
  const notes = readFileSync(notesPath, 'utf8');
  const requiredSections = ['## Release Checks', '## Known Issues', '## Upgrade Notes', '## Recent Changes', '## Artifacts'];
  for (const section of requiredSections) {
    if (!notes.includes(section)) {
      errors.push(`Release notes are missing required section ${section}: ${toRepoPath(notesPath)}`);
    }
  }
  verifyNonEmptyReleaseList(notes, 'Known Issues', notesPath);
  verifyNonEmptyReleaseList(notes, 'Upgrade Notes', notesPath);
}

function verifyChecksums() {
  const checksumPath = join(releaseDir, `SHA256SUMS-${version}.txt`);
  if (!existsSync(checksumPath)) {
    const releaseFiles = existsSync(releaseDir) ? listFiles(releaseDir) : [];
    if (releaseFiles.length) {
      warnings.push(`Missing checksum file for existing release directory: ${toRepoPath(checksumPath)}`);
    } else {
      errors.push(`Missing release directory: ${toRepoPath(releaseDir)}`);
    }
    return;
  }

  checkedFiles.push(toRepoPath(checksumPath));
  const lines = readFileSync(checksumPath, 'utf8')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (!lines.length) {
    warnings.push(`Checksum file has no entries: ${toRepoPath(checksumPath)}`);
    return;
  }

  for (const line of lines) {
    const match = line.match(/^([a-fA-F0-9]{64})\s{2,}(.+)$/);
    if (!match) {
      errors.push(`Invalid checksum line: ${line}`);
      continue;
    }

    const expectedHash = match[1].toLowerCase();
    const repoPath = normalizeRepoPath(match[2]);
    if (!isSafeArtifactRepoPath(repoPath)) {
      errors.push(`Checksum references unsafe artifact path: ${repoPath}`);
      continue;
    }
    const artifactPath = join(rootDir, ...repoPath.split('/'));
    if (!existsSync(artifactPath)) {
      errors.push(`Checksum references missing file: ${repoPath}`);
      continue;
    }

    const actualHash = sha256File(artifactPath);
    checksumEntries.add(repoPath);
    checkedFiles.push(repoPath);
    if (actualHash !== expectedHash) {
      errors.push(`Checksum mismatch for ${repoPath}: expected ${expectedHash}, got ${actualHash}`);
    }
  }
}

function verifyRuleFeedArtifacts() {
  const signedFeedPath = join(releaseDir, `rule-feed-${version}.signed.json`);
  const signReportPath = join(releaseDir, `rule-feed-sign-${version}.json`);
  const checkReportPath = join(releaseDir, `rule-feed-check-${version}.json`);
  const paths = [signedFeedPath, signReportPath, checkReportPath];
  const existing = paths.filter((path) => existsSync(path));

  if (!existing.length) {
    return;
  }

  for (const path of paths) {
    if (!existsSync(path)) {
      errors.push(`Incomplete signed rule feed artifacts; missing ${toRepoPath(path)}`);
    } else {
      const repoPath = toRepoPath(path);
      checkedFiles.push(repoPath);
      if (!checksumEntries.has(repoPath)) {
        errors.push(`Signed rule feed artifact is missing from checksum file: ${repoPath}`);
      }
    }
  }

  if (existsSync(signReportPath)) {
    const signReport = readJson(signReportPath);
    const serialized = JSON.stringify(signReport).toLowerCase();
    if (serialized.includes('private_key') || serialized.includes('private-key')) {
      errors.push(`Rule feed sign report contains private key material fields: ${toRepoPath(signReportPath)}`);
    }
    if (!signReport.public_key_hex) {
      errors.push(`Rule feed sign report is missing public_key_hex: ${toRepoPath(signReportPath)}`);
    }
    if (!signReport.signature) {
      errors.push(`Rule feed sign report is missing signature: ${toRepoPath(signReportPath)}`);
    }
  }

  if (existsSync(checkReportPath)) {
    const checkReport = readJson(checkReportPath);
    if (checkReport.passed !== true) {
      errors.push(`Rule feed check report did not pass: ${toRepoPath(checkReportPath)}`);
    }
    if (existsSync(signedFeedPath) && checkReport.signature_verified !== true) {
      errors.push(`Signed rule feed check did not verify the signature: ${toRepoPath(checkReportPath)}`);
    }
  }
}

function verifySmartScreenPackage() {
  const packagePath = join(releaseDir, 'smartscreen', `smartscreen-submission-${version}.json`);
  if (!existsSync(packagePath)) {
    return;
  }

  checkedFiles.push(toRepoPath(packagePath));
  const submissionPackage = readJson(packagePath);
  const blockedKey = findBlockedKey(submissionPackage);
  if (blockedKey) {
    errors.push(`SmartScreen submission package contains blocked sensitive field ${blockedKey}: ${toRepoPath(packagePath)}`);
  }
  if (containsPrivateKeyMaterial(submissionPackage)) {
    errors.push(`SmartScreen submission package appears to contain private key material: ${toRepoPath(packagePath)}`);
  }
  if (submissionPackage.product !== 'Aegis WebShield AI') {
    errors.push(`SmartScreen submission package has unexpected product: ${toRepoPath(packagePath)}`);
  }
  if (submissionPackage.version !== version) {
    errors.push(`SmartScreen submission package version does not match release version: ${toRepoPath(packagePath)}`);
  }
  if (!Array.isArray(submissionPackage.checklist) || !submissionPackage.checklist.length) {
    errors.push(`SmartScreen submission package must include a checklist: ${toRepoPath(packagePath)}`);
  }
  if (submissionPackage.evidence_files !== undefined && !Array.isArray(submissionPackage.evidence_files)) {
    errors.push(`SmartScreen submission package evidence_files must be an array: ${toRepoPath(packagePath)}`);
  }
  if (Array.isArray(submissionPackage.evidence_files)) {
    for (const [index, evidenceFile] of submissionPackage.evidence_files.entries()) {
      if (!evidenceFile || typeof evidenceFile.path !== 'string' || typeof evidenceFile.present !== 'boolean') {
        errors.push(`SmartScreen submission package evidence file ${index} is incomplete: ${toRepoPath(packagePath)}`);
        continue;
      }
      const repoPath = normalizeRepoPath(evidenceFile.path);
      if (!isSafeArtifactRepoPath(repoPath)) {
        errors.push(`SmartScreen submission package evidence file ${index} has unsafe path: ${repoPath}`);
        continue;
      }
      const evidencePath = join(rootDir, ...repoPath.split('/'));
      const actualPresent = existsSync(evidencePath);
      if (actualPresent !== evidenceFile.present) {
        errors.push(`SmartScreen submission package evidence file ${index} presence mismatch for ${repoPath}`);
      }
    }
  }
  if (submissionPackage.artifacts !== undefined && !Array.isArray(submissionPackage.artifacts)) {
    errors.push(`SmartScreen submission package artifacts must be an array: ${toRepoPath(packagePath)}`);
  }
  if (Array.isArray(submissionPackage.artifacts)) {
    for (const [index, artifact] of submissionPackage.artifacts.entries()) {
      if (!artifact || typeof artifact.path !== 'string' || typeof artifact.sha256 !== 'string') {
        errors.push(`SmartScreen submission package artifact ${index} is incomplete: ${toRepoPath(packagePath)}`);
        continue;
      }
      if (!/^[a-fA-F0-9]{64}$/.test(artifact.sha256)) {
        errors.push(`SmartScreen submission package artifact ${index} has invalid sha256: ${toRepoPath(packagePath)}`);
        continue;
      }

      const repoPath = normalizeRepoPath(artifact.path);
      if (!isSafeArtifactRepoPath(repoPath)) {
        errors.push(`SmartScreen submission package artifact ${index} has unsafe path: ${repoPath}`);
        continue;
      }
      if (!basename(repoPath).includes(`_${version}_`)) {
        errors.push(`SmartScreen submission package artifact ${index} does not match current version ${version}: ${repoPath}`);
      }
      const artifactPath = join(rootDir, ...repoPath.split('/'));
      if (!existsSync(artifactPath)) {
        errors.push(`SmartScreen submission package artifact ${index} references missing file: ${repoPath}`);
        continue;
      }
      const actualHash = sha256File(artifactPath);
      if (actualHash !== artifact.sha256.toLowerCase()) {
        errors.push(`SmartScreen submission package artifact ${index} checksum mismatch for ${repoPath}: expected ${artifact.sha256.toLowerCase()}, got ${actualHash}`);
      }
      if (!checksumEntries.has(repoPath)) {
        errors.push(`SmartScreen submission package artifact ${index} is missing from checksum file: ${repoPath}`);
      }
    }
  }

  const packagedArtifacts = Array.isArray(submissionPackage.artifacts) ? submissionPackage.artifacts : [];
  if (Array.isArray(submissionPackage.evidence_files)) {
    for (const evidenceFile of submissionPackage.evidence_files) {
      if (!evidenceFile?.present || typeof evidenceFile.path !== 'string') {
        continue;
      }
      const repoPath = normalizeRepoPath(evidenceFile.path);
      if (repoPath === 'release/signature-verification.json' || repoPath.startsWith('release/installer-smoke/')) {
        const evidencePath = join(rootDir, ...repoPath.split('/'));
        if (!artifactEvidenceMatches(evidencePath, packagedArtifacts)) {
          errors.push(`SmartScreen evidence does not cover current packaged artifacts: ${repoPath}`);
        }
      }
    }
  }
}

function artifactEvidenceMatches(path, expectedArtifacts) {
  if (!existsSync(path) || expectedArtifacts.length === 0) {
    return false;
  }
  let evidence;
  try {
    evidence = JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
  } catch {
    return false;
  }
  if (!Array.isArray(evidence.artifacts) || evidence.artifacts.length !== expectedArtifacts.length) {
    return false;
  }
  const byPath = new Map(
    evidence.artifacts.map((artifact) => [normalizeRepoPath(artifact?.path ?? ''), artifact])
  );
  return byPath.size === expectedArtifacts.length && expectedArtifacts.every((expected) => {
    const actual = byPath.get(normalizeRepoPath(expected?.path ?? ''));
    return actual
      && actual.size_bytes === expected.size_bytes
      && String(actual.sha256 ?? '').toLowerCase() === String(expected.sha256 ?? '').toLowerCase();
  });
}

function findBlockedKey(value) {
  if (!value || typeof value !== 'object') {
    return null;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (/private|password|token|api[_-]?key|secret/i.test(key)) {
      return key;
    }
    const nestedResult = findBlockedKey(nested);
    if (nestedResult) {
      return nestedResult;
    }
  }
  return null;
}

function containsPrivateKeyMaterial(value) {
  if (typeof value === 'string') {
    return /-----BEGIN [A-Z ]*PRIVATE KEY-----/i.test(value);
  }
  if (!value || typeof value !== 'object') {
    return false;
  }
  return Object.values(value).some((nested) => containsPrivateKeyMaterial(nested));
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
  } catch (error) {
    errors.push(`Unable to parse JSON ${toRepoPath(path)}: ${error.message}`);
    return {};
  }
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

function verifyNonEmptyReleaseList(notes, section, notesPath) {
  const escapedSection = section.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = notes.match(new RegExp(`## ${escapedSection}\\n\\n([\\s\\S]*?)(?:\\n## |$)`));
  if (!match) {
    return;
  }
  const hasListItem = match[1]
    .split(/\r?\n/)
    .some((line) => line.trim().startsWith('- ') && line.trim().length > 2);
  if (!hasListItem) {
    errors.push(`Release notes section ${section} must include at least one list item: ${toRepoPath(notesPath)}`);
  }
}

function toRepoPath(path) {
  return normalizeRepoPath(path.replace(rootDir, '').replace(/^[/\\]/, ''));
}

function normalizeRepoPath(path) {
  return path.replaceAll('\\', '/');
}

function isSafeArtifactRepoPath(path) {
  if (!path || path.startsWith('/') || /^[A-Za-z]:/.test(path)) {
    return false;
  }
  return path
    .split('/')
    .every((segment) => segment && segment !== '.' && segment !== '..');
}
