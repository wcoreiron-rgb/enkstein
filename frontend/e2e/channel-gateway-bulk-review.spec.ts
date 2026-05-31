import { expect, test } from '@playwright/test';

test('channel gateway supports bulk approve for pending commands', async ({ page }) => {
  let pendingCommands = [
    {
      command_id: 'cmd-bulk-1',
      timestamp: new Date().toISOString(),
      actor: 'analyst@company.com',
      action: 'run_swarm',
      target: 'identity_risk',
      outcome: 'requires_approval',
      risk_score: 86,
      policy_name: 'seeded_requires_approval',
      reason: 'needs approval',
      required_approvals: 1,
      approvals_received: 0,
      approval_status: 'pending',
    },
    {
      command_id: 'cmd-bulk-2',
      timestamp: new Date().toISOString(),
      actor: 'analyst@company.com',
      action: 'run_scan',
      target: 'cloud',
      outcome: 'requires_approval',
      risk_score: 70,
      policy_name: 'seeded_requires_approval',
      reason: 'needs approval',
      required_approvals: 1,
      approvals_received: 0,
      approval_status: 'pending',
    },
  ];

  await page.route('**/api/v1/channel-gateway/messages**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ total: 0, messages: [] }),
    });
  });
  await page.route('**/api/v1/channel-gateway/stats', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        total_messages: 0,
        allowed: 0,
        blocked: 0,
        pending_approval: 2,
        identity_verified: 0,
        slack_messages: 0,
        teams_messages: 0,
        dispatched_runs: 0,
        registered_identities: 0,
        trusted_identities: 0,
        connected_channels: 2,
      }),
    });
  });
  await page.route('**/api/v1/channel-gateway/identities**', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
  });
  await page.route('**/api/v1/commands/pending**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ count: pendingCommands.length, commands: pendingCommands }),
    });
  });

  let bulkSeen = false;
  await page.route('**/api/v1/commands/bulk-review', async (route) => {
    bulkSeen = true;
    const payload = route.request().postDataJSON() as any;
    expect(payload.decision).toBe('approve');
    expect(payload.command_ids).toEqual(expect.arrayContaining(['cmd-bulk-1', 'cmd-bulk-2']));
    pendingCommands = [];
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ processed: 2, approved: 2, rejected: 0, errors: [] }),
    });
  });

  await page.goto('/channel-gateway');
  await page.getByRole('button', { name: 'Commands' }).click();
  await expect(page.getByText('Pending Command Approvals')).toBeVisible();

  await page.getByRole('button', { name: 'Select visible' }).click();
  await page.getByRole('button', { name: 'Bulk Approve (2)' }).click();

  await expect(page.getByText('No pending commands right now.')).toBeVisible();
  expect(bulkSeen).toBeTruthy();
});
