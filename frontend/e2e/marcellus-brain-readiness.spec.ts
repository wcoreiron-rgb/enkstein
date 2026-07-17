import { expect, test } from './fixtures';
import type { Page } from '@playwright/test';

const unavailable = [
  { brain: 'claude_subscription', kind: 'subscription', available: false, authenticated: false, status: 'unavailable', detail: 'Native Brain Bridge is starting.' },
  { brain: 'claude_browser', kind: 'browser_session', available: false, authenticated: false, status: 'unavailable', detail: 'Browser companion is unavailable.' },
];

const ready = [
  { brain: 'claude_subscription', kind: 'subscription', available: true, authenticated: true, status: 'ready', runtime: 'Claude Code CLI', detail: 'Ready', last_checked: '2026-07-17T18:00:00Z' },
  { brain: 'claude_browser', kind: 'browser_session', available: true, authenticated: true, status: 'ready', runtime: 'Visible browser', detail: 'Ready' },
];

async function mockBrainDependencies(page: Page) {
  // Keep this UI test hermetic: a development backend may be running on the
  // configured API origin, so any unrelated layout request must not return a
  // real 401 and lock the test console. More-specific mocks registered below
  // and by each test take precedence in Playwright's LIFO route order.
  await page.route('**/api/v1/**', (route) => route.fulfill({ json: {} }));
  await page.route('**/api/v1/marcellus/workspace/projects**', (route) => route.fulfill({ json: [] }));
  await page.route('**/api/v1/marcellus/workspace/conversations**', (route) => route.fulfill({ json: [] }));
  await page.route('**/api/v1/arcclaw/providers', (route) => route.fulfill({ json: [] }));
  await page.route('**/api/v1/modelclaw/profiles', (route) => route.fulfill({ json: [] }));
  await page.route('**/api/v1/arcclaw/agent/models', (route) => route.fulfill({ json: {} }));
}

test('Brain readiness retries launch failures and refreshes stale state on focus', async ({ page }) => {
  let calls = 0;
  let hostReady = false;
  await mockBrainDependencies(page);
  await page.route('**/api/v1/modelclaw/brains/status**', (route) => {
    calls += 1;
    return route.fulfill({ json: hostReady ? ready : unavailable });
  });

  await page.goto('/marcellus/brains');
  await expect(page.getByText('Unavailable', { exact: true }).first()).toBeVisible();
  await expect.poll(() => calls).toBeGreaterThanOrEqual(3);
  await expect(page.getByTitle('Refresh connections')).toBeEnabled();
  hostReady = true;
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await expect(page.getByText('Ready', { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Claude Browser Session' })).toHaveCount(0);
  expect(calls).toBeGreaterThanOrEqual(4);
});

test('manual refresh performs a forced readiness check', async ({ page }) => {
  let calls = 0;
  let hostReady = false;
  await mockBrainDependencies(page);
  await page.route('**/api/v1/modelclaw/brains/status**', (route) => {
    calls += 1;
    return route.fulfill({ json: hostReady ? ready : [{ ...unavailable[0], status: 'needs_setup', detail: 'Run claude auth login.' }] });
  });

  await page.goto('/marcellus/brains');
  await expect(page.getByText('Needs setup', { exact: true }).first()).toBeVisible();
  const refresh = page.getByTitle('Refresh connections');
  await expect(refresh).toBeEnabled();
  hostReady = true;
  await refresh.click();
  await expect(page.getByText('Ready', { exact: true }).first()).toBeVisible();
  expect(calls).toBeGreaterThanOrEqual(2);
});
