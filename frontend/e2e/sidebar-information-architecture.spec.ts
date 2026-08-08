/**
 * The blade offers three workspace modes, and each mode's children stay inside
 * it. Security keeps its Arms expanded; Chat and Cowork show their own panels.
 */
import { expect, test } from './fixtures';
import { mockMarcellusWorkspace } from './marcellus-workspace-mocks';

const TOP_LEVEL = ['Chat', 'Cowork', 'Security'];

test('the workspace switch offers all three modes', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.goto('/marcellus');

  for (const label of TOP_LEVEL) {
    await expect(page.getByTitle(label).first()).toBeVisible();
  }
});

test('light theme uses the red/orange mark', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.addInitScript(() => window.localStorage.setItem('rc-theme', 'light'));
  await page.goto('/marcellus');
  const src = await page.locator('img[alt="Enkstein"]').first().getAttribute('src');
  expect(src).toBe('/enkstein-icon.png');
});

test('dark theme uses the white-on-dark mark', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.addInitScript(() => window.localStorage.setItem('rc-theme', 'dark'));
  await page.goto('/marcellus');
  // The provider resolves the stored theme in an effect, so assert on the
  // settled value rather than the first paint.
  await expect(page.locator('img[alt="Enkstein"]').first())
    .toHaveAttribute('src', '/enkstein-icon-dark.png');
});

test('security expands its arms on demand', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.goto('/marcellus');
  await page.getByTitle('Security').click();
  await expect(page.getByRole('link', { name: 'Control Center' })).toBeVisible();
  // Arms collapse by default so the blade stays short; opening one reveals it.
  await expect(page.getByRole('link', { name: 'Cloud Security' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Protection Arm' }).click();
  await expect(page.getByRole('link', { name: 'Cloud Security' })).toBeVisible();
});

test('cowork shows its own projects, not chat conversations', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.goto('/marcellus');
  await page.getByTitle('Cowork').click();
  await expect(page.getByLabel('Cowork project')).toBeVisible();
  await expect(page.getByLabel('Chat folder', { exact: true })).toHaveCount(0);
});

/**
 * A published newer release must be discoverable without opening the macOS
 * menu bar, which is the only place the old build surfaced it, and which
 * Windows does not have at all.
 */
test('a newer published release surfaces an update action', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.route('**/api/v1/runtime/update', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        update_available: true,
        current_version: '0.8.3',
        latest_version: '0.9.1',
        status: 'update_available',
        release_url: 'https://github.com/wcoreiron-rgb/enkstein/releases/tag/v0.9.1',
        macos_download_url: 'https://example.invalid/Enkstein-0.9.1-macos.pkg',
        windows_download_url: null,
      }),
    }),
  );
  await page.goto('/marcellus');
  await expect(page.getByText('Update to v0.9.1')).toBeVisible();
});

test('a current install shows no update action', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.route('**/api/v1/runtime/update', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        update_available: false,
        current_version: '0.8.3',
        latest_version: '0.8.3',
        status: 'current',
      }),
    }),
  );
  await page.goto('/marcellus');
  await expect(page.getByText(/^Update to v/)).toHaveCount(0);
});

test('an unreachable release feed never shows an error', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.route('**/api/v1/runtime/update', (route) => route.abort());
  await page.goto('/marcellus');
  await expect(page.getByText(/^Update to v/)).toHaveCount(0);
  await expect(page.getByTitle('Security').first()).toBeVisible();
});

/** A collapsed blade must still signal a pending release. */
test('a collapsed sidebar still signals an available update', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.route('**/api/v1/runtime/update', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        update_available: true,
        current_version: '0.8.3',
        latest_version: '0.9.1',
        status: 'update_available',
        release_url: 'https://github.com/wcoreiron-rgb/enkstein/releases/tag/v0.9.1',
        macos_download_url: 'https://example.invalid/Enkstein-0.9.1-macos.pkg',
        windows_download_url: null,
      }),
    }),
  );
  await page.goto('/marcellus');
  await page.getByTitle('Collapse sidebar').click();
  await expect(page.getByLabel('Update to v0.9.1 available')).toBeVisible();
});
