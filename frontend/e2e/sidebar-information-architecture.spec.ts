/**
 * The blade must open as three workspace modes rather than the full module list,
 * and each category's children must stay inside it.
 */
import { expect, test } from './fixtures';
import { mockMarcellusWorkspace } from './marcellus-workspace-mocks';

const TOP_LEVEL = ['Chat', 'Cowork', 'Security'];

test('sidebar opens as three modes with nested features hidden', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.goto('/marcellus');

  for (const label of TOP_LEVEL) {
    await expect(page.getByRole('button', { name: label, exact: false }).first()).toBeVisible();
  }
  // Security Arms belong to Security and must not leak into the default view.
  await expect(page.getByRole('link', { name: 'Cloud Security' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Threat Intelligence' })).toHaveCount(0);
});

test('an expanded category is remembered across a reload', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.goto('/marcellus');
  await page.getByTitle('Security').click();
  await expect(page.getByRole('link', { name: 'Control Center' })).toBeVisible();

  await page.reload();
  await expect(page.getByRole('link', { name: 'Control Center' })).toBeVisible();
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

test('security expands its arms only when opened', async ({ page }) => {
  await mockMarcellusWorkspace(page);
  await page.goto('/marcellus');
  await page.getByTitle('Security').click();
  await expect(page.getByRole('link', { name: 'Control Center' })).toBeVisible();
  // Arms are their own disclosure, still closed under Security.
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
