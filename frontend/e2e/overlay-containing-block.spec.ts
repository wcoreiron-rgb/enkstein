import { test, expect } from './fixtures';

/**
 * Overlays must escape any ancestor that establishes a containing block.
 *
 * `position: fixed` is normally positioned against the viewport, but an
 * ancestor with `backdrop-filter`, `filter`, `transform`, `perspective`, or
 * `contain` clamps it to that ancestor's box instead. Liquid Glass gives every
 * card a `backdrop-filter`, so a drawer rendered inside a connector card
 * collapsed to the card's bounds and read as embedded content rather than a
 * sheet over the page.
 *
 * This shipped because WebKit enforces the rule and Blink does not: the
 * packaged desktop app is WKWebView, so Chromium-only testing measured the
 * drawer as correct in all three themes while every real user saw it broken.
 * These run under `@webkit` for that reason. Asserting geometry alone would
 * miss the cause, so a probe element is also mounted as a sibling of the
 * overlay: if it fails to fill the viewport, an ancestor is containing it.
 */
const CONNECTOR = [{
  id: 'c1', name: 'Entra', connector_type: 'entra_id', category: 'Identity & Access',
  status: 'pending', risk_level: 'medium', trust_score: 72, is_configured: true,
  description: 'D', approved_scopes: '[]', requested_scopes: '[]',
  network_access: true, shell_access: false,
}];

const SCOPE = {
  connector_type: 'entra_id', canonical_type: 'entra_id', adapter_state: 'native',
  configured: true, assesses_controls: true, collectors: [], controls: [],
  counts: { in_scope: 0, pass: 0, fail: 0, not_assessed: 0 },
};

async function openControlScope(page: import('@playwright/test').Page, theme: string) {
  await page.route('**/api/v1/connectors', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(CONNECTOR),
  }));
  await page.route('**/controls/connector-scope/**', (route) => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(SCOPE),
  }));
  await page.goto('/connectors', { waitUntil: 'networkidle' });
  await page.evaluate((t) => localStorage.setItem('rc-theme', t), theme);
  await page.reload({ waitUntil: 'networkidle' });
  await page.locator('.rounded-xl button').last().click();
  await page.getByRole('button', { name: 'See controls' }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
}

for (const theme of ['dark', 'light', 'liquid']) {
  test(`@webkit control scope drawer fills the viewport in ${theme}`, async ({ page }) => {
    await openControlScope(page, theme);

    const viewport = page.viewportSize()!;
    const box = (await page.getByRole('dialog').boundingBox())!;
    expect(box.x).toBe(0);
    expect(box.y).toBe(0);
    expect(Math.round(box.height)).toBe(viewport.height);
    expect(Math.round(box.width)).toBeGreaterThanOrEqual(viewport.width - 20);
  });
}

test('@webkit no ancestor contains the control scope overlay', async ({ page }) => {
  await openControlScope(page, 'liquid');

  const probe = await page.evaluate(() => {
    const dialog = document.querySelector('[role="dialog"]')!;
    const el = document.createElement('div');
    el.style.cssText = 'position:fixed;inset:0;pointer-events:none';
    dialog.parentElement!.appendChild(el);
    const rect = el.getBoundingClientRect();
    el.remove();
    return { width: rect.width, height: rect.height, x: rect.x, y: rect.y };
  });

  const viewport = page.viewportSize()!;
  expect(probe.x).toBe(0);
  expect(probe.y).toBe(0);
  expect(Math.round(probe.height)).toBe(viewport.height);
});

test('@webkit overlay is a direct child of body, not of a glass card', async ({ page }) => {
  await openControlScope(page, 'liquid');

  const parentIsBody = await page.evaluate(() => {
    const dialog = document.querySelector('[role="dialog"]')!;
    return dialog.parentElement === document.body;
  });
  expect(parentIsBody).toBe(true);
});
