// Headless screenshot capture for README/marketing.
//
// Owner login requires a TOTP code that cannot be scripted, so mint a real
// token signed with the running instance's SECRET_KEY and hand it to the app.
// Stubbing /auth/me instead would authenticate the shell while every data call
// still returned 401, producing screenshots of empty panels and `undefined`.
//
//   cd "$HOME/Library/Application Support/Marcellus/runtime"
//   SK=$(grep '^SECRET_KEY=' .env | cut -d= -f2-)
//   SHOT_TOKEN=$(python -c "import jwt,datetime,sys;print(jwt.encode({'sub':'admin','role':'super_admin','tenant_id':'default','exp':datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=2)},sys.argv[1],algorithm='HS256'))" "$SK")
//   SHOT_TOKEN=$SHOT_TOKEN SHOT_BASE=http://localhost:3001 node e2e/capture-screenshots.mjs
//
// The packaged runtime publishes the UI on 3001; a dev server uses 3000.
import { chromium } from 'playwright';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(__dirname, '../../docs/screenshots');
const BASE = process.env.SHOT_BASE || 'http://localhost:3000';
const TOKEN = process.env.SHOT_TOKEN;

if (!TOKEN) {
  console.error('SHOT_TOKEN is required — see the header comment for how to mint one.');
  process.exit(1);
}

const PAGES = [
  ['chat',           '/marcellus/chat'],
  ['cowork',         '/marcellus/cowork'],
  ['brains',         '/marcellus/brains'],
  ['security',       '/marcellus/security'],
  ['dashboard',      '/dashboard'],
  ['trust-fabric',   '/trust-fabric'],
  ['swarm',          '/swarm'],
  ['remediation',    '/remediation'],
  ['control-center', '/control-center'],
  ['connectors',     '/connectors'],
  ['zero-trust',     '/zero-trust'],
];

const run = async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,           // retina-crisp
    colorScheme: 'dark',
  });
  await ctx.addInitScript((token) => {
    window.sessionStorage.setItem('marcellus_session_token', token);
  }, TOKEN);
  const page = await ctx.newPage();

  for (const [name, route] of PAGES) {
    try {
      await page.goto(`${BASE}${route}`, { waitUntil: 'networkidle', timeout: 30000 });
      await page.waitForTimeout(2500);  // let charts/data settle
      // Fail loudly rather than shipping a screenshot of the login page.
      if (new URL(page.url()).pathname.startsWith('/login')) {
        console.log(`⚠️  ${name}: redirected to /login, skipping`);
        continue;
      }
      await page.screenshot({ path: path.join(OUT, `${name}.png`) });
      console.log(`✅ ${name}.png`);
    } catch (e) {
      console.log(`⚠️  ${name}: ${e.message.split('\n')[0]}`);
    }
  }
  await browser.close();
};

run();
