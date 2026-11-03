import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { preview } from 'vite';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const output = join(root, 'release', 'community-ui', new Date().toISOString().replace(/[:.]/g, '-'));
mkdirSync(output, { recursive: true });
const server = await preview({ root, preview: { host: '127.0.0.1', port: 0, strictPort: false } });
let browser;
try {
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  page.setDefaultTimeout(15000);
  await page.addInitScript(() => {
    window.__communityExports = [];
    const usage = { monthly_scans: 10000, projects: 1000, targets: 1000, reports: 10000, ai_fix_guides: 10000, active_scans: 0 };
    window.__TAURI_INTERNALS__ = { invoke: async (command, args) => {
      if (command === 'local_usage_status') return usage;
      if (command === 'record_report_export') {
        window.__communityExports.push(args.input);
        return { usage };
      }
      throw new Error('Native command unavailable in this isolated UI test');
    } };
  });
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}`, { waitUntil: 'networkidle' });
  assert.equal(await page.getByRole('heading', { name: 'License', exact: true }).count(), 0);
  const text = await page.locator('body').innerText();
  assert.doesNotMatch(text, /Activate Pro|Use Free|Pro feature|Plan & usage|Review Pro/);
  assert.match(text, /10000 scans this month/);
  const guide = page.getByRole('button', { name: 'Generate guide', exact: true });
  assert.equal(await guide.isEnabled(), true);
  await guide.click();
  assert.equal(await page.getByText('Save a user API key before generating an AI Fix Guide.', { exact: true }).count(), 1);
  await guide.scrollIntoViewIfNeeded();
  await page.screenshot({ path: join(output, 'ai-guide.png') });
  const formats = page.locator('select').filter({ has: page.locator('option[value="pdf"]') });
  for (const format of ['pdf', 'sarif']) {
    await formats.selectOption(format);
    const downloading = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Export findings', exact: true }).click();
    const download = await downloading;
    assert.ok(download.suggestedFilename().endsWith(`.${format}`));
  }
  const exports = await page.evaluate(() => window.__communityExports);
  assert.equal(exports.length, 2);
  assert.equal(exports[0].format, 'pdf');
  assert.ok(exports[0].artifact_content.startsWith('%PDF-1.4'));
  assert.equal(JSON.parse(exports[1].artifact_content).version, '2.1.0');
  await formats.scrollIntoViewIfNeeded();
  await page.screenshot({ path: join(output, 'reports.png') });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: join(output, 'dashboard.png') });
  console.log('Community UI passed: no activation UI, high usage accepted, PDF/SARIF exports, AI requires only a user key. Native commands were mocked; no provider calls were made.');
} finally {
  if (browser) await browser.close();
  await new Promise((resolve, reject) => server.httpServer.close((error) => error ? reject(error) : resolve()));
}
