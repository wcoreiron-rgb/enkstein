// Headless screenshot capture for README/marketing.
// Run: node e2e/capture-screenshots.mjs   (requires the app running on :3000)
import { chromium } from 'playwright';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(__dirname, '../../docs/screenshots');
const BASE = process.env.SHOT_BASE || 'http://localhost:3000';

const PAGES = [
  ['dashboard',      '/dashboard'],
  ['arcclaw',        '/arcclaw'],
  ['swarm',          '/swarm'],
  ['remediation',    '/remediation'],
  ['trust-fabric',   '/trust-fabric'],
  ['control-center', '/control-center'],
  ['connectors',     '/connectors'],
];

const run = async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,           // retina-crisp
    colorScheme: 'dark',
  });
  const page = await ctx.newPage();

  for (const [name, route] of PAGES) {
    try {
      await page.goto(`${BASE}${route}`, { waitUntil: 'networkidle', timeout: 30000 });
      await page.waitForTimeout(2500);  // let charts/data settle
      await page.screenshot({ path: path.join(OUT, `${name}.png`) });
      console.log(`✅ ${name}.png`);
    } catch (e) {
      console.log(`⚠️  ${name}: ${e.message.split('\n')[0]}`);
    }
  }
  await browser.close();
};

run();
