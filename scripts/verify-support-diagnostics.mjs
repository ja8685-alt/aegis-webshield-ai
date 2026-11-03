import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const jsonOutput = args.includes('--json');
const fileArg = args.find((arg) => !arg.startsWith('--'));
const errors = [];
const warnings = [];
const blockedStructuredKeys = new Set([
  'api_key',
  'approval_note',
  'artifact_content',
  'authorization',
  'cookie',
  'endpoint',
  'evidence',
  'evidence_json',
  'license_key',
  'license_key_hash',
  'password',
  'private_key',
  'prompt',
  'provider_response',
  'request_body',
  'response_body',
  'secret',
  'secret_value',
  'set-cookie',
  'target_url',
  'url'
]);

if (!fileArg) {
  errors.push('Usage: node scripts/verify-support-diagnostics.mjs <diagnostics.json> [--json]');
  finish();
}

if (!isSafeRepoRelativePath(normalizeRepoPath(fileArg))) {
  errors.push('diagnostics path must be a safe repository-relative path');
  finish();
}

const filePath = resolveRepoPath(fileArg);
if (!existsSync(filePath)) {
  errors.push(`Diagnostics file not found: ${fileArg}`);
  finish();
}

let raw = '';
let diagnostics = {};
try {
  raw = readFileSync(filePath, 'utf8');
  diagnostics = JSON.parse(raw.replace(/^\uFEFF/, ''));
} catch (error) {
  errors.push(`Unable to parse diagnostics JSON: ${error.message}`);
  finish();
}

verifyRequiredShape(diagnostics);
verifySensitiveContent(raw);
finish();

function verifyRequiredShape(value) {
  requireString(value.product, 'product');
  requireString(value.app_version, 'app_version');
  requireString(value.generated_at, 'generated_at');
  requireObject(value.platform, 'platform');
  requireObject(value.storage, 'storage');
  requireObject(value.usage, 'usage');
  if (value.edition === 'community') {
    if ('license' in value) errors.push('community diagnostics must omit legacy license/account metadata');
  } else {
    requireObject(value.license, 'legacy license');
  }
  requireObject(value.engine, 'engine');
  requireObject(value.rule_pack, 'rule_pack');
  if (!Array.isArray(value.recent_audit_logs)) {
    errors.push('recent_audit_logs must be an array');
  } else if (value.recent_audit_logs.length > 20) {
    errors.push('recent_audit_logs must contain at most 20 records');
  } else {
    value.recent_audit_logs.forEach((record, index) => verifyAuditLogRecord(record, index));
  }

  if (value.storage) {
    requireNumber(value.storage.project_count, 'storage.project_count');
    requireNumber(value.storage.target_count, 'storage.target_count');
    if ('database_path' in value.storage) {
      errors.push('storage.database_path must not be included');
    }
  }
  if (value.license) {
    if ('license_key' in value.license || 'license_key_hash' in value.license) {
      errors.push('license key material must not be included');
    }
  }
}

function verifyAuditLogRecord(record, index) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    errors.push(`recent_audit_logs[${index}] must be an object`);
    return;
  }

  for (const blockedField of ['id', 'actor_user_id', 'entity_id']) {
    if (blockedField in record) {
      errors.push(`recent_audit_logs[${index}].${blockedField} must not be included`);
    }
  }

  requireString(record.action, `recent_audit_logs[${index}].action`);
  requireString(record.entity_type, `recent_audit_logs[${index}].entity_type`);
  requireString(record.severity, `recent_audit_logs[${index}].severity`);
  requireString(record.created_at, `recent_audit_logs[${index}].created_at`);

  if (typeof record.metadata_json_redacted !== 'string') {
    errors.push(`recent_audit_logs[${index}].metadata_json_redacted must be a string`);
    return;
  }

  let metadata = {};
  try {
    metadata = JSON.parse(record.metadata_json_redacted);
  } catch (error) {
    errors.push(`recent_audit_logs[${index}].metadata_json_redacted must contain JSON: ${error.message}`);
    return;
  }
  verifyNoBlockedStructuredFields(metadata, `recent_audit_logs[${index}].metadata_json_redacted`);
}

function verifySensitiveContent(rawValue) {
  const sensitivePatterns = [
    [/sk-[A-Za-z0-9_-]{12,}/, 'OpenAI-style API key'],
    [/https?:\/\/[^\s"']+/i, 'raw URL'],
    [/authorization\s*:\s*bearer/i, 'Authorization bearer value'],
    [/"authorization"\s*:/i, 'authorization field'],
    [/"password"\s*:/i, 'password field'],
    [/"private_key"\s*:/i, 'private_key field'],
    [/"license_key"\s*:/i, 'license_key field'],
    [/"license_key_hash"\s*:/i, 'license_key_hash field'],
    [/"approval_note"\s*:/i, 'approval_note field'],
    [/"target_url"\s*:/i, 'target_url field'],
    [/"endpoint"\s*:/i, 'endpoint field'],
    [/"url"\s*:/i, 'url field'],
    [/"evidence_json"\s*:/i, 'evidence_json field'],
    [/"evidence"\s*:/i, 'evidence field'],
    [/"artifact_content"\s*:/i, 'report body field'],
    [/"request_body"\s*:/i, 'request_body field'],
    [/"response_body"\s*:/i, 'response_body field'],
    [/"prompt"\s*:/i, 'raw prompt field'],
    [/"provider_response"\s*:/i, 'provider_response field'],
    [/"api_key"\s*:/i, 'api_key field'],
    [/"secret_value"\s*:/i, 'secret_value field'],
    [/"set-cookie"\s*:/i, 'set-cookie field'],
    [/"cookie"\s*:/i, 'cookie field']
  ];
  for (const [pattern, label] of sensitivePatterns) {
    if (pattern.test(rawValue)) {
      errors.push(`Diagnostics contains sensitive ${label}`);
    }
  }
}

function verifyNoBlockedStructuredFields(value, path) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => verifyNoBlockedStructuredFields(item, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') {
    if (typeof value === 'string' && /https?:\/\/[^\s"']+/i.test(value)) {
      errors.push(`${path} contains a raw URL`);
    }
    return;
  }

  for (const [key, child] of Object.entries(value)) {
    const normalized = key.toLowerCase();
    if (blockedStructuredKeys.has(normalized)) {
      errors.push(`${path}.${key} must not be included in support diagnostics`);
    }
    verifyNoBlockedStructuredFields(child, `${path}.${key}`);
  }
}

function requireString(value, field) {
  if (typeof value !== 'string' || !value.trim()) {
    errors.push(`${field} must be a non-empty string`);
  }
}

function requireNumber(value, field) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    errors.push(`${field} must be a number`);
  }
}

function requireObject(value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    errors.push(`${field} must be an object`);
  }
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

function finish() {
  const summary = {
    file: fileArg || null,
    passed: errors.length === 0,
    warning_count: warnings.length,
    error_count: errors.length,
    warnings,
    errors
  };
  if (jsonOutput) {
    console.log(JSON.stringify(summary, null, 2));
  } else {
    console.log(`Support diagnostics verification: ${summary.passed ? 'passed' : 'failed'}`);
    if (warnings.length) {
      console.log('\nWarnings:');
      warnings.forEach((warning) => console.log(`- ${warning}`));
    }
    if (errors.length) {
      console.log('\nErrors:');
      errors.forEach((error) => console.log(`- ${error}`));
    }
  }
  process.exit(errors.length ? 2 : 0);
}
