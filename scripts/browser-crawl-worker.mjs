#!/usr/bin/env node

import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_WAIT_MS = 1500;
const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_MAX_REQUESTS = 500;
const MAX_WAIT_MS = 10000;
const MAX_TIMEOUT_MS = 60000;
const MAX_CAPTURED_REQUESTS = 1000;
const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));

function parseArgs(argv) {
  const options = {
    headless: true,
    waitMs: DEFAULT_WAIT_MS,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    maxRequests: DEFAULT_MAX_REQUESTS
  };

  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--help' || value === '-h') {
      options.help = true;
    } else if (value === '--url') {
      options.url = argv[++index];
    } else if (value === '--out') {
      options.out = argv[++index];
    } else if (value === '--approval-note') {
      options.approvalNote = argv[++index];
    } else if (value === '--show-browser') {
      options.headless = false;
    } else if (value === '--wait-ms') {
      options.waitMs = parseBoundedPositiveInteger(argv[++index], '--wait-ms', MAX_WAIT_MS);
    } else if (value === '--timeout-ms') {
      options.timeoutMs = parseBoundedPositiveInteger(argv[++index], '--timeout-ms', MAX_TIMEOUT_MS);
    } else if (value === '--max-requests') {
      options.maxRequests = parseBoundedPositiveInteger(argv[++index], '--max-requests', MAX_CAPTURED_REQUESTS);
    } else {
      throw new Error(`Unknown option: ${value}`);
    }
  }

  return options;
}

function parseBoundedPositiveInteger(value, name, max) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  if (parsed > max) {
    throw new Error(`${name} must be at most ${max}`);
  }
  return parsed;
}

function printHelp() {
  console.log(`Aegis browser crawl worker

Usage:
  node scripts/browser-crawl-worker.mjs --url https://example.com --approval-note "Owner approval captured in SEC-123" --out ./.aegis/browser-observation.json

Options:
  --url             Approved HTTP/HTTPS URL to open.
  --approval-note   Required authorization note for auditability.
  --out             Safe repository-relative JSON output path for browser observations.
  --show-browser    Run Chromium visibly instead of headless mode.
  --wait-ms         Extra wait after load. Default: ${DEFAULT_WAIT_MS}. Max: ${MAX_WAIT_MS}.
  --timeout-ms      Navigation timeout. Default: ${DEFAULT_TIMEOUT_MS}. Max: ${MAX_TIMEOUT_MS}.
  --max-requests    Maximum captured document/fetch/XHR requests. Default: ${DEFAULT_MAX_REQUESTS}. Max: ${MAX_CAPTURED_REQUESTS}.
`);
}

function validateOptions(options) {
  if (options.help) {
    return;
  }
  if (!options.url) {
    throw new Error('--url is required');
  }
  if (!options.out) {
    throw new Error('--out is required');
  }
  if (!isSafeRepoRelativePath(normalizeRepoPath(options.out))) {
    throw new Error('--out must be a safe repository-relative path');
  }
  if (!options.approvalNote || !options.approvalNote.trim()) {
    throw new Error('--approval-note is required');
  }

  const url = new URL(options.url);
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('--url must use http or https');
  }
}

async function loadPlaywright() {
  try {
    return await import('playwright');
  } catch (error) {
    throw new Error(
      `Playwright is not available. Run "npm install" and "npx playwright install chromium" before browser crawling. ${error.message}`
    );
  }
}

async function runBrowserCrawl(options) {
  const { chromium } = await loadPlaywright();
  const browser = await chromium.launch({ headless: options.headless });
  const context = await browser.newContext({
    ignoreHTTPSErrors: false,
    userAgent: 'AegisWebShieldAI/0.1 browser-crawler'
  });
  const page = await context.newPage();
  const routes = new Set();
  const requests = [];
  const seenRequests = new Set();

  await page.addInitScript(() => {
    const pushRoute = () => {
      window.__aegisRoutes = window.__aegisRoutes || [];
      window.__aegisRoutes.push(window.location.href);
    };
    const wrapHistory = (name) => {
      const original = window.history[name];
      window.history[name] = function aegisHistoryWrapper(...args) {
        const result = original.apply(this, args);
        pushRoute();
        return result;
      };
    };
    wrapHistory('pushState');
    wrapHistory('replaceState');
    window.addEventListener('popstate', pushRoute);
    window.addEventListener('hashchange', pushRoute);
    pushRoute();
  });

  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) {
      routes.add(sanitizeObservationUrl(frame.url()));
    }
  });

  page.on('request', (request) => {
    const resourceType = request.resourceType();
    if (!['document', 'fetch', 'xhr'].includes(resourceType)) {
      return;
    }
    if (requests.length >= options.maxRequests) {
      return;
    }
    const sanitizedUrl = sanitizeObservationUrl(request.url());
    const key = `${request.method()} ${sanitizedUrl} ${resourceType}`;
    if (seenRequests.has(key)) {
      return;
    }
    seenRequests.add(key);
    requests.push({
      method: request.method(),
      url: sanitizedUrl,
      resource_type: resourceType
    });
  });

  try {
    await page.goto(options.url, {
      waitUntil: 'networkidle',
      timeout: options.timeoutMs
    });
    await page.waitForTimeout(options.waitMs);
    const observedRoutes = await page.evaluate(() => window.__aegisRoutes || []);
    for (const route of observedRoutes) {
      routes.add(sanitizeObservationUrl(route));
    }
  } finally {
    await context.close();
    await browser.close();
  }

  return {
    seed_url: options.url,
    approval_note_present: Boolean(options.approvalNote && options.approvalNote.trim()),
    captured_at: new Date().toISOString(),
    routes: [...routes].sort(),
    requests
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  validateOptions(options);
  if (options.help) {
    printHelp();
    return;
  }

  const result = await runBrowserCrawl(options);
  const outputPath = resolveRepoPath(options.out);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  console.log(`Browser crawl observation saved: ${outputPath}`);
  console.log(`Routes: ${result.routes.length}`);
  console.log(`Requests: ${result.requests.length}`);
}

function sanitizeObservationUrl(value) {
  try {
    const url = new URL(value);
    const parameterNames = [...new Set([...url.searchParams.keys()])].sort();
    url.search = '';
    for (const name of parameterNames) {
      if (name.trim()) {
        url.searchParams.append(name, '');
      }
    }
    url.hash = '';
    return url.toString();
  } catch {
    return value;
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

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
