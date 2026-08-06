import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:3100',
    trace: 'on-first-retry',
  },
  webServer: {
    command: 'npm run dev -- --hostname 127.0.0.1 --port 3100',
    url: 'http://127.0.0.1:3100',
    reuseExistingServer: true,
    timeout: 120_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
      // The demo recorder is a content tool, not a check. A cosmetic timing
      // drift there must never read as a product regression.
      grepInvert: /@demo/,
    },
    // The packaged desktop app is WKWebView. WebKit enforces containing-block
    // rules that Blink does not, so overlay/layout regressions can be invisible
    // in Chromium and broken for every shipped user. Specs that assert layout
    // affected by those rules opt in via `@webkit`.
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
      grep: /@webkit/,
    },
    // Opt-in recorder: `npx playwright test demo-recording --project=demo`.
    // Records at the 1440x900 the demo script calls for, at 2x scale so the
    // capture survives being cropped or scaled up in an editor.
    {
      name: 'demo',
      grep: /@demo/,
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1440, height: 900 },
        deviceScaleFactor: 2,
        video: { mode: 'on', size: { width: 2880, height: 1800 } },
      },
    },
  ],
});
