import { expect, test as base } from '@playwright/test';

export const test = base.extend({
  page: async ({ page }, applyFixture) => {
    await page.addInitScript(() => {
      window.sessionStorage.setItem('marcellus_session_token', 'e2e-owner-session');
    });
    await page.route('**/api/v1/auth/me', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          sub: 'e2e-owner',
          email: 'owner@example.test',
          role: 'super_admin',
          tenant_id: 'default',
        }),
      });
    });
    await applyFixture(page);
  },
});

export { expect };
