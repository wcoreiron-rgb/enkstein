// Record a short Enkstein app tour with Dark, Light, and Liquid Glass.
//
// The script never reads a secret itself. Give it a short-lived real owner JWT
// in SHOT_TOKEN (the same token used by capture-screenshots.mjs):
//
//   SHOT_TOKEN=... SHOT_BASE=http://localhost:3001 \
//     node e2e/record-demo-video.mjs
//
// Output: docs/demo/enkstein-tour.webm. The recording is a product overview,
// not a security claim: it deliberately avoids showing simulated findings as
// though they were live customer data.
import { chromium } from 'playwright';
import { fileURLToPath } from 'url';
import fs from 'fs/promises';
import path from 'path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const outputDir = path.join(root, 'docs', 'demo');
const base = process.env.SHOT_BASE || 'http://localhost:3000';
const token = process.env.SHOT_TOKEN;

if (!token) {
  console.error('SHOT_TOKEN is required. See capture-screenshots.mjs for a safe local token recipe.');
  process.exit(1);
}

const wait = (page, ms) => page.waitForTimeout(ms);
const wallpaper = `
  html.liquid {
    background-image:
      radial-gradient(1200px 800px at 18% 12%, #2f5d8a 0%, transparent 60%),
      radial-gradient(1000px 900px at 82% 78%, #7a4a6d 0%, transparent 58%),
      linear-gradient(140deg, #14202e 0%, #1d2b3a 45%, #241f2e 100%) !important;
    background-attachment: fixed !important;
  }
`;

async function visit(page, route, ms) {
  await page.goto(`${base}${route}`, { waitUntil: 'networkidle', timeout: 30_000 });
  await wait(page, ms);
}

async function setTheme(page, theme) {
  await page.evaluate((nextTheme) => {
    window.localStorage.setItem('rc-theme', nextTheme);
    if (nextTheme === 'liquid') window.localStorage.setItem('rc-glass', 'balanced');
  }, theme);
}

await fs.mkdir(outputDir, { recursive: true });
const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  deviceScaleFactor: 1,
  recordVideo: { dir: outputDir, size: { width: 1440, height: 900 } },
});
await context.addInitScript((ownerToken) => {
  window.sessionStorage.setItem('marcellus_session_token', ownerToken);
  window.localStorage.setItem('rc-theme', 'dark');
}, token);
const page = await context.newPage();

await visit(page, '/marcellus/cowork', 4_000);
await visit(page, '/marcellus/brains', 5_000);

await setTheme(page, 'light');
await visit(page, '/marcellus/cowork', 5_000);

await setTheme(page, 'liquid');
await visit(page, '/marcellus/security', 2_500);
await page.addStyleTag({ content: wallpaper });
await wait(page, 5_000);

const video = page.video();
await page.close();
await context.close();
await browser.close();

const generatedPath = await video.path();
const outputPath = path.join(outputDir, 'enkstein-tour.webm');
await fs.rename(generatedPath, outputPath);
console.log(`Recorded ${outputPath}`);
