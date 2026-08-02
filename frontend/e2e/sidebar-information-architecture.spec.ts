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

test('security shows its arms', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.goto('/marcellus');
  await page.getByTitle('Security').click();
  await expect(page.getByRole('link', { name: 'Control Center' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Cloud Security' })).toBeVisible();
});

test('cowork shows its own projects, not chat conversations', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.goto('/marcellus');
  await page.getByTitle('Cowork').click();
  await expect(page.getByLabel('Cowork project')).toBeVisible();
  await expect(page.getByLabel('Chat folder', { exact: true })).toHaveCount(0);
});
