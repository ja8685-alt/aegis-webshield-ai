import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const jsonOutput = args.includes('--json');
const errors = [];
const warnings = [];

const configPath = join(rootDir, 'src-tauri', 'tauri.conf.json');
const config = readJson(configPath);
const csp = config?.app?.security?.csp;

if (typeof csp !== 'string' || !csp.trim()) {
  errors.push('Tauri app.security.csp must be a non-empty string for release candidates.');
} else {
  verifyCsp(csp);
}

const summary = {
  passed: errors.length === 0,
  error_count: errors.length,
  warning_count: warnings.length,
  errors,
  warnings
};

if (jsonOutput) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  console.log(`Tauri security config verification: ${summary.passed ? 'passed' : 'failed'}`);
  errors.forEach((error) => console.log(`- error: ${error}`));
  warnings.forEach((warning) => console.log(`- warning: ${warning}`));
}

if (errors.length) {
  process.exit(2);
}

function verifyCsp(value) {
  const directives = parseCsp(value);
  for (const required of [
    'default-src',
    'script-src',
    'style-src',
    'img-src',
    'connect-src',
    'object-src',
    'base-uri',
    'form-action',
    'frame-ancestors'
  ]) {
    if (!directives.has(required)) {
      errors.push(`CSP is missing required directive: ${required}.`);
    }
  }

  const forbiddenTokens = new Set(["'unsafe-inline'", "'unsafe-eval'"]);
  for (const [directive, sources] of directives) {
    for (const source of sources) {
      if (forbiddenTokens.has(source)) {
        errors.push(`CSP ${directive} must not include ${source}.`);
      }
      if (source === '*') {
        errors.push(`CSP ${directive} must not include wildcard source *.`);
      }
      if (/^http:$/i.test(source) || /^http:\/\//i.test(source)) {
        const allowedLocalhost = directive === 'connect-src' && source === 'http://ipc.localhost';
        const allowedAssetHost = directive === 'img-src' && source === 'http://asset.localhost';
        if (!allowedLocalhost && !allowedAssetHost) {
          errors.push(`CSP ${directive} must not allow insecure HTTP source ${source}.`);
        }
      }
    }
  }

  if (!hasOnlySources(directives, 'object-src', ["'none'"])) {
    errors.push("CSP object-src must be 'none'.");
  }
  if (!hasOnlySources(directives, 'base-uri', ["'none'"])) {
    errors.push("CSP base-uri must be 'none'.");
  }
  if (!hasOnlySources(directives, 'form-action', ["'none'"])) {
    errors.push("CSP form-action must be 'none'.");
  }
  if (!hasOnlySources(directives, 'frame-ancestors', ["'none'"])) {
    errors.push("CSP frame-ancestors must be 'none'.");
  }

  const connectSources = directives.get('connect-src') ?? [];
  if (!connectSources.includes('ipc:') || !connectSources.includes('http://ipc.localhost')) {
    warnings.push('CSP connect-src should include Tauri IPC sources: ipc: and http://ipc.localhost.');
  }
}

function parseCsp(value) {
  const directives = new Map();
  for (const part of value.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) {
      continue;
    }
    directives.set(tokens[0].toLowerCase(), tokens.slice(1));
  }
  return directives;
}

function hasOnlySources(directives, name, expected) {
  const sources = directives.get(name) ?? [];
  return sources.length === expected.length && expected.every((source) => sources.includes(source));
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
  } catch (error) {
    errors.push(`Unable to parse ${path}: ${error.message}`);
    return {};
  }
}
