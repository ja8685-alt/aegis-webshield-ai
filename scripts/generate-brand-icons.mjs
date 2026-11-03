import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const outputDir = new URL('../src-tauri/icons/', import.meta.url);
mkdirSync(outputDir, { recursive: true });

const crcTable = Array.from({ length: 256 }, (_, index) => {
  let crc = index;
  for (let bit = 0; bit < 8; bit += 1) {
    crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
  }
  return crc >>> 0;
});

const sizes = [32, 128, 256];
const pngs = sizes.map((size) => ({
  size,
  bytes: encodePng(size, size, drawIcon(size))
}));

for (const image of pngs) {
  const name = image.size === 256 ? '128x128@2x.png' : `${image.size}x${image.size}.png`;
  writeFileSync(join(outputDir.pathname, name), image.bytes);
}

writeFileSync(join(outputDir.pathname, 'icon.ico'), encodeIco(pngs));

function drawIcon(size) {
  const pixels = Buffer.alloc(size * size * 4);
  const radius = size * 0.18;
  const shield = [
    [0.5, 0.15],
    [0.79, 0.28],
    [0.72, 0.68],
    [0.5, 0.86],
    [0.28, 0.68],
    [0.21, 0.28]
  ];

  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const index = (y * size + x) * 4;
      const insideRoundRect = roundedRect(x + 0.5, y + 0.5, size, radius);
      if (!insideRoundRect) {
        pixels[index + 3] = 0;
        continue;
      }

      const t = (x + y) / (size * 2);
      setPixel(pixels, index, mix([23, 107, 135], [18, 86, 108], t), 255);

      const nx = (x + 0.5) / size;
      const ny = (y + 0.5) / size;
      if (pointInPolygon(nx, ny, shield)) {
        setPixel(pixels, index, [236, 253, 243], 255);
      }

      const stroke = Math.max(1.6, size * 0.035);
      const aLeft = distanceToSegment(x, y, size * 0.36, size * 0.68, size * 0.5, size * 0.31);
      const aRight = distanceToSegment(x, y, size * 0.64, size * 0.68, size * 0.5, size * 0.31);
      const aBar = distanceToSegment(x, y, size * 0.42, size * 0.53, size * 0.58, size * 0.53);
      if (aLeft < stroke || aRight < stroke || aBar < stroke) {
        setPixel(pixels, index, [18, 33, 47], 255);
      }

      const pulse = distanceToSegment(x, y, size * 0.29, size * 0.72, size * 0.71, size * 0.72);
      if (pulse < Math.max(1, size * 0.012)) {
        setPixel(pixels, index, [125, 211, 252], 255);
      }
    }
  }

  return pixels;
}

function roundedRect(x, y, size, radius) {
  const min = radius;
  const max = size - radius;
  const cx = clamp(x, min, max);
  const cy = clamp(y, min, max);
  const dx = x - cx;
  const dy = y - cy;
  return dx * dx + dy * dy <= radius * radius;
}

function pointInPolygon(x, y, polygon) {
  let inside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i, i += 1) {
    const xi = polygon[i][0];
    const yi = polygon[i][1];
    const xj = polygon[j][0];
    const yj = polygon[j][1];
    const intersects = yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi;
    if (intersects) {
      inside = !inside;
    }
  }
  return inside;
}

function distanceToSegment(px, py, ax, ay, bx, by) {
  const abx = bx - ax;
  const aby = by - ay;
  const apx = px - ax;
  const apy = py - ay;
  const t = clamp((apx * abx + apy * aby) / (abx * abx + aby * aby), 0, 1);
  const dx = px - (ax + abx * t);
  const dy = py - (ay + aby * t);
  return Math.sqrt(dx * dx + dy * dy);
}

function encodePng(width, height, rgba) {
  const scanlines = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    scanlines[y * (width * 4 + 1)] = 0;
    rgba.copy(scanlines, y * (width * 4 + 1) + 1, y * width * 4, (y + 1) * width * 4);
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', uint32(width), uint32(height), Buffer.from([8, 6, 0, 0, 0])),
    chunk('IDAT', deflateSync(scanlines)),
    chunk('IEND')
  ]);
}

function encodeIco(images) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);

  const entries = [];
  let offset = header.length + images.length * 16;
  for (const image of images) {
    const entry = Buffer.alloc(16);
    entry[0] = image.size === 256 ? 0 : image.size;
    entry[1] = image.size === 256 ? 0 : image.size;
    entry[2] = 0;
    entry[3] = 0;
    entry.writeUInt16LE(1, 4);
    entry.writeUInt16LE(32, 6);
    entry.writeUInt32LE(image.bytes.length, 8);
    entry.writeUInt32LE(offset, 12);
    entries.push(entry);
    offset += image.bytes.length;
  }

  return Buffer.concat([header, ...entries, ...images.map((image) => image.bytes)]);
}

function chunk(type, ...buffers) {
  const data = Buffer.concat(buffers);
  const typeBuffer = Buffer.from(type, 'ascii');
  return Buffer.concat([uint32(data.length), typeBuffer, data, uint32(crc32(Buffer.concat([typeBuffer, data])))]);
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc = (crc >>> 8) ^ crcTable[(crc ^ byte) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function uint32(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value >>> 0);
  return buffer;
}

function setPixel(pixels, index, rgb, alpha) {
  pixels[index] = rgb[0];
  pixels[index + 1] = rgb[1];
  pixels[index + 2] = rgb[2];
  pixels[index + 3] = alpha;
}

function mix(left, right, t) {
  return left.map((value, index) => Math.round(value + (right[index] - value) * t));
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}
