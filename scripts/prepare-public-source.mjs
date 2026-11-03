import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateRawSync } from 'node:zlib';

const repositoryRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const binaryFiles = new Set([
  'src-tauri/icons/icon.ico', 'src-tauri/icons/32x32.png',
  'src-tauri/icons/128x128.png', 'src-tauri/icons/128x128@2x.png',
]);
const blockedSegments = /^(?:\.git|\.env(?:\..*)?|\.npmrc|\.netrc|\.ssh|\.aws|\.azure|\.cargo|node_modules|target|dist|release|artifacts|public-source|test-results|playwright-report)$/i;
const blockedExtension = /\.(?:db(?:-.*)?|sqlite[3]?(?:-.*)?|pem|key|pfx|p12|jks|keystore|log|dmp|exe|msi|zip|bak|backup)$/i;
const safeExtension = /\.(?:rs|toml|lock|json|tsx?|css|html|mjs|ps1|md|ya?ml|sql)$/i;
const rootNames = new Set(['LICENSE', 'NOTICE', '.gitignore', '.gitattributes']);
const forbiddenText = [
  ['private Git remote', /\bgit@[a-z0-9.-]+:[^\s]+/i],
  ['personal Windows path', /\b[A-Z]:[\\/]+Users[\\/]+[^\s\\/]+[\\/]/i],
  ['personal Unix path', /\/(?:home|Users)\/[a-z0-9_.-]+\//i],
  ['credential-bearing URL', /\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s/@:]+:[^\s/@]+@/i],
  ['private licensing marker', /license\s*=\s*"(?:UNLICENSED|Proprietary)"/],
];

export function validatePublicPath(file) {
  if (typeof file !== 'string' || !file || file.includes('\\') || file.includes(':') || /[\x00-\x1f\x7f]/.test(file)) {
    throw new Error('Unsafe public path');
  }
  const parts = file.split('/');
    if (parts.some((part) => !part || part === '.' || part === '..' || part.endsWith('.') || part.endsWith(' ') || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part) || blockedSegments.test(part))) {
    throw new Error(`Excluded public path: ${file}`);
  }
  if (blockedExtension.test(file) || (!safeExtension.test(file) && !rootNames.has(file) && !binaryFiles.has(file) && !file.endsWith('/.gitignore'))) {
    throw new Error(`Excluded public file type: ${file}`);
  }
  if (/^(?:AGENTS\.md|docs\/(?:design|research|ideas)\/)/i.test(file)) {
    throw new Error(`Internal document cannot be published: ${file}`);
  }
  return file;
}

export function inspectPublicFile(root, file) {
  validatePublicPath(file);
  let path = resolve(root);
  if (lstatSync(path).isSymbolicLink()) throw new Error('Source root cannot be a symlink');
  const segments = file.split('/');
  for (let index = 0; index < segments.length; index++) {
    path = join(path, segments[index]);
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || (index < segments.length - 1 && !stat.isDirectory())) {
      throw new Error(`Symlink or invalid parent in public path: ${file}`);
    }
  }
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.size > 8 * 1024 * 1024) throw new Error(`Invalid public file size/type: ${file}`);
  const bytes = readFileSync(path);
  if (!binaryFiles.has(file)) {
    const content = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (content.includes('\0')) throw new Error(`Binary content in source file: ${file}`);
    for (const [label, pattern] of forbiddenText) {
      if (pattern.test(content)) throw new Error(`${label} in ${file}; value withheld`);
    }
  }
  return { file, bytes };
}

export function loadPublicFiles(root) {
  const manifest = JSON.parse(readFileSync(join(root, 'scripts/public-source-files.json'), 'utf8'));
  if (manifest.schema_version !== 1 || !Array.isArray(manifest.files) || !manifest.files.length) {
    throw new Error('Invalid public source inventory');
  }
  const seen = new Set();
  const files = manifest.files.map((file) => {
    validatePublicPath(file);
    const key = file.toLowerCase();
    if (seen.has(key)) throw new Error(`Duplicate public path: ${file}`);
    seen.add(key);
    return inspectPublicFile(root, file);
  });
  for (const required of ['README.md', 'LICENSE', 'NOTICE', 'SECURITY.md', 'CONTRIBUTING.md', 'Cargo.toml', 'Cargo.lock', 'package.json', 'package-lock.json', 'scripts/public-source-files.json']) {
    if (!seen.has(required.toLowerCase())) throw new Error(`Missing required public file: ${required}`);
  }
  if (files.reduce((sum, entry) => sum + entry.bytes.length, 0) > 64 * 1024 * 1024) throw new Error('Source package exceeds size budget');
  return files.sort((a, b) => a.file.localeCompare(b.file, 'en'));
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function sourceZip(files) {
  const local = [], central = [];
  let offset = 0;
  for (const { file, bytes } of files) {
    validatePublicPath(file);
    const name = Buffer.from(file, 'utf8'), compressed = deflateRawSync(bytes), crc = crc32(bytes);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50); header.writeUInt16LE(20, 4); header.writeUInt16LE(0x800, 6);
    header.writeUInt16LE(8, 8); header.writeUInt16LE(33, 12); // fixed 1980-01-01, no private source timestamps
    header.writeUInt32LE(crc, 14); header.writeUInt32LE(compressed.length, 18);
    header.writeUInt32LE(bytes.length, 22); header.writeUInt16LE(name.length, 26);
    local.push(header, name, compressed);
    const directory = Buffer.alloc(46);
    directory.writeUInt32LE(0x02014b50); directory.writeUInt16LE(20, 4); directory.writeUInt16LE(20, 6);
    directory.writeUInt16LE(0x800, 8); directory.writeUInt16LE(8, 10); directory.writeUInt16LE(33, 14);
    directory.writeUInt32LE(crc, 16); directory.writeUInt32LE(compressed.length, 20);
    directory.writeUInt32LE(bytes.length, 24); directory.writeUInt16LE(name.length, 28);
    directory.writeUInt32LE(offset, 42); central.push(directory, name);
    offset += header.length + name.length + compressed.length;
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, directory, end]);
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function prepare() {
  const files = loadPublicFiles(repositoryRoot);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const output = join(repositoryRoot, 'release', 'public-source', stamp);
  const source = join(output, 'source');
  if (existsSync(output)) throw new Error('Publication output already exists');
  // Refuse redirected output parents too; never write through a junction/symlink.
  for (const parent of [join(repositoryRoot, 'release'), join(repositoryRoot, 'release', 'public-source')]) {
    if (existsSync(parent) && (lstatSync(parent).isSymbolicLink() || !lstatSync(parent).isDirectory())) throw new Error('Unsafe publication output parent');
  }
  mkdirSync(source, { recursive: true });
  for (const { file, bytes } of files) {
    const destination = join(source, ...file.split('/'));
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, bytes, { flag: 'wx' });
  }
  const scan = spawnSync('gitleaks', ['dir', source, '--redact=100', '--no-banner', '--no-color', '--ignore-gitleaks-allow', '--report-format', 'json', '--report-path', join(output, 'secret-scan.json')], {
    cwd: source, encoding: 'utf8', windowsHide: true, timeout: 120000,
    env: Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.toUpperCase().startsWith('GITLEAKS_'))),
  });
  if (scan.error || scan.status !== 0) {
    throw new Error('Public secret scan failed or Gitleaks is unavailable. No ZIP was created; inspect the redacted secret-scan.json in the private output directory.');
  }
  const zip = sourceZip(files);
  writeFileSync(join(output, 'source.zip'), zip, { flag: 'wx' });
  const manifest = {
    schema_version: 1, edition: 'community', history_included: false,
    secret_scan: { tool: 'gitleaks', passed: true },
    archive: { file: 'source.zip', size: zip.length, sha256: sha256(zip) },
    files: files.map(({ file, bytes }) => ({ file, size: bytes.length, sha256: sha256(bytes) })),
  };
  writeFileSync(join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ output: output.slice(repositoryRoot.length + sep.length).split(sep).join('/'), files: files.length, secret_scan: 'passed', archive_sha256: manifest.archive.sha256 }, null, 2));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { prepare(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
