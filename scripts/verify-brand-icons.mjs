import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const jsonOutput = process.argv.includes('--json');
const errors = [];
const checked = [];

const tauriConfig = readJson(join(rootDir, 'src-tauri', 'tauri.conf.json'));
const expectedIcons = [
  { path: 'src-tauri/icons/32x32.png', width: 32, height: 32 },
  { path: 'src-tauri/icons/128x128.png', width: 128, height: 128 },
  { path: 'src-tauri/icons/128x128@2x.png', width: 256, height: 256 },
  { path: 'src-tauri/icons/icon.ico', icoSizes: [32, 128, 256] }
];

verifyTauriIconConfig();
for (const icon of expectedIcons) {
  verifyIcon(icon);
}

const summary = {
  passed: errors.length === 0,
  checked_icons: checked,
  error_count: errors.length,
  errors
};

if (jsonOutput) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.log(`Brand icon verification: ${summary.passed ? 'passed' : 'failed'}`);
  console.log(`Checked icons: ${checked.length}`);
  if (errors.length) {
    console.log('\nErrors:');
    errors.forEach((error) => console.log(`- ${error}`));
  }
}

if (errors.length) {
  process.exit(2);
}

function verifyTauriIconConfig() {
  const configured = tauriConfig.bundle?.icon;
  if (!Array.isArray(configured)) {
    errors.push('src-tauri/tauri.conf.json bundle.icon must be an array.');
    return;
  }
  const normalized = new Set(configured.map((value) => String(value).replaceAll('\\', '/')));
  for (const icon of expectedIcons) {
    const tauriPath = icon.path.replace(/^src-tauri\//, '');
    if (!normalized.has(tauriPath)) {
      errors.push(`Tauri bundle.icon is missing ${tauriPath}.`);
    }
  }
}

function verifyIcon(icon) {
  const absolutePath = join(rootDir, ...icon.path.split('/'));
  if (!existsSync(absolutePath)) {
    errors.push(`Missing icon asset: ${icon.path}`);
    return;
  }
  const bytes = readFileSync(absolutePath);
  if (icon.path.endsWith('.png')) {
    const dimensions = readPngDimensions(bytes);
    if (!dimensions) {
      errors.push(`Invalid PNG icon: ${icon.path}`);
      return;
    }
    checked.push({ path: icon.path, width: dimensions.width, height: dimensions.height });
    if (dimensions.width !== icon.width || dimensions.height !== icon.height) {
      errors.push(`Unexpected PNG dimensions for ${icon.path}: ${dimensions.width}x${dimensions.height}`);
    }
  } else if (icon.path.endsWith('.ico')) {
    const sizes = readIcoSizes(bytes);
    checked.push({ path: icon.path, sizes });
    for (const size of icon.icoSizes) {
      if (!sizes.includes(size)) {
        errors.push(`ICO asset ${icon.path} is missing ${size}x${size} image.`);
      }
    }
  }
}

function readPngDimensions(bytes) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (bytes.length < 24 || !bytes.subarray(0, 8).equals(signature)) {
    return null;
  }
  const chunkType = bytes.subarray(12, 16).toString('ascii');
  if (chunkType !== 'IHDR') {
    return null;
  }
  return {
    width: bytes.readUInt32BE(16),
    height: bytes.readUInt32BE(20)
  };
}

function readIcoSizes(bytes) {
  if (bytes.length < 6 || bytes.readUInt16LE(0) !== 0 || bytes.readUInt16LE(2) !== 1) {
    errors.push('Invalid ICO header.');
    return [];
  }
  const count = bytes.readUInt16LE(4);
  const sizes = [];
  for (let index = 0; index < count; index += 1) {
    const offset = 6 + index * 16;
    if (offset + 16 > bytes.length) {
      errors.push('ICO directory is truncated.');
      break;
    }
    const width = bytes[offset] === 0 ? 256 : bytes[offset];
    const height = bytes[offset + 1] === 0 ? 256 : bytes[offset + 1];
    if (width === height) {
      sizes.push(width);
    }
  }
  return sizes;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
}
