import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateRawSync } from 'node:zlib';
import test from 'node:test';
import { inspectPublicFile, loadPublicFiles, sourceZip, validatePublicPath } from '../scripts/prepare-public-source.mjs';

function removeTestDirectory(root) {
  assert.equal(dirname(resolve(root)), resolve(tmpdir()));
  assert.ok(basename(root).startsWith('aegis-public-test-'));
  rmSync(root, { recursive: true, force: true });
}

test('publication refuses credentials, data, traversal, and Windows path aliases', () => {
  for (const path of ['../README.md', '/README.md', 'C:/secret.txt', 'src\\main.tsx', '.git/config', '.env', '.env.production', 'keys/key.pem', 'data/app.sqlite-wal', 'data/app.db', 'node_modules/pkg/index.js', 'README.md:private', 'docs/../README.md', 'src./main.tsx', 'docs/research/private.md']) {
    assert.throws(() => validatePublicPath(path), undefined, path);
  }
  assert.equal(validatePublicPath('src-tauri/migrations/0001_initial_local_store.sql'), 'src-tauri/migrations/0001_initial_local_store.sql');
});

test('publication refuses a directory symlink/junction and does not touch its target', () => {
  const root = mkdtempSync(join(tmpdir(), 'aegis-public-test-'));
  try {
    mkdirSync(join(root, 'actual'));
    writeFileSync(join(root, 'actual/file.md'), 'private');
    symlinkSync(join(root, 'actual'), join(root, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
    assert.throws(() => inspectPublicFile(root, 'linked/file.md'), /Symlink/);
  } finally { removeTestDirectory(root); }
});

test('publication reports private connection/path categories without exposing their contents', () => {
  const root = mkdtempSync(join(tmpdir(), 'aegis-public-test-'));
  try {
    for (const content of [['git', '@internal.example:private/repo.git'].join(''), ['postgres', '://example-user:example-password@database.invalid/app'].join(''), ['C:', 'Users', 'example-person', 'repo'].join('\\')]) {
      writeFileSync(join(root, 'README.md'), content);
      assert.throws(() => inspectPublicFile(root, 'README.md'), (error) => error.message.includes('value withheld') && !error.message.includes(content));
    }
  } finally { removeTestDirectory(root); }
});

test('source ZIP round-trips Unicode and binary bytes with relative names', () => {
  const entries = [{ file: 'README.md', bytes: Buffer.from('한국어 / English\n') }, { file: 'src-tauri/icons/32x32.png', bytes: Buffer.from([0, 128, 255, 10]) }];
  const zip = sourceZip(entries);
  let offset = 0;
  for (const entry of entries) {
    assert.equal(zip.readUInt32LE(offset), 0x04034b50);
    const length = zip.readUInt32LE(offset + 18), nameLength = zip.readUInt16LE(offset + 26);
    assert.equal(zip.subarray(offset + 30, offset + 30 + nameLength).toString(), entry.file);
    const data = offset + 30 + nameLength;
    assert.deepEqual(inflateRawSync(zip.subarray(data, data + length)), entry.bytes);
    offset = data + length;
  }
  assert.equal(zip.readUInt32LE(offset), 0x02014b50);
  assert.equal(zip.readUInt32LE(zip.length - 22), 0x06054b50);
});

test('reviewed public inventory contains only publishable files and bilingual documentation', () => {
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  const entries = loadPublicFiles(root);
  const readme = entries.find((entry) => entry.file === 'README.md').bytes.toString('utf8');
  assert.match(readme, /## 한국어/);
  assert.match(readme, /## English/);
  assert.ok(entries.some((entry) => entry.file === '.github/workflows/ci.yml'));
  assert.ok(entries.every((entry) => !entry.file.startsWith('.git/')));
});

test('diagnostics accept community output and continue rejecting sensitive or malformed legacy metadata', () => {
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  const release = join(root, 'release');
  mkdirSync(release, { recursive: true });
  const folder = mkdtempSync(join(release, 'publication-test-'));
  const file = join(folder, 'diagnostics.json');
  const fixture = {
    product: 'Aegis WebShield AI', app_version: '1.0.0', generated_at: '2026-11-03',
    edition: 'community', platform: {}, storage: { project_count: 0, target_count: 0 },
    usage: {}, engine: {}, rule_pack: {}, recent_audit_logs: [],
  };
  const verify = (document) => {
    writeFileSync(file, JSON.stringify(document));
    return spawnSync(process.execPath, ['scripts/verify-support-diagnostics.mjs', `release/${basename(folder)}/diagnostics.json`, '--json'], { cwd: root, encoding: 'utf8', windowsHide: true }).status;
  };
  try {
    assert.equal(verify(fixture), 0);
    assert.notEqual(verify({ ...fixture, license: { online_account_id: 'synthetic-account' } }), 0);
    assert.notEqual(verify({ ...fixture, edition: undefined, license: 'not-an-object' }), 0);
    assert.notEqual(verify({ ...fixture, storage: { ...fixture.storage, password: 'synthetic-placeholder' } }), 0);
    assert.equal(verify({ ...fixture, edition: undefined, license: { plan: 'free', status: 'free' } }), 0);
  } finally {
    assert.equal(dirname(resolve(folder)), resolve(release));
    assert.ok(basename(folder).startsWith('publication-test-'));
    rmSync(folder, { recursive: true, force: true });
  }
});
