import { expect, test } from './fixtures';
import { createWorkspaceStore, mockMarcellusWorkspace, mockTurnStream, seedArtifacts } from './marcellus-workspace-mocks';
import type { WorkspaceStore } from './marcellus-workspace-mocks';

const POWERSHELL = [
  '$ErrorActionPreference = "Stop"',
  '$resourceGroup = "governed-rg"',
  '$locations = @("eastus", "westus2", "northeurope", "australiaeast")',
  'foreach ($location in $locations) {',
  '  Write-Host "Provisioning a very long descriptive resource name in $location to force horizontal scrolling of this code fence"',
  '  New-AzResourceGroup -Name "$resourceGroup-$location" -Location $location -Tag @{ environment = "production"; owner = "enkstein" }',
  '}',
  'Write-Host "Terminal PowerShell line marker 9f3a done"',
].join('\n');

const MARKDOWN = [
  '# Deployment plan',
  '',
  'Here is the **governed** rollout with a [runbook](https://example.com/runbook).',
  '',
  '- First governed step',
  '- Second governed step',
  '',
  '| Stage | Owner |',
  '| --- | --- |',
  '| Build | CI |',
  '',
  'Use `inline-token` inline. Raw HTML like <img src=x onerror=alert(1)> must be inert.',
  '',
  '```powershell',
  POWERSHELL,
  '```',
].join('\n');

function seedChat(store: WorkspaceStore, id: string) {
  const now = new Date().toISOString();
  store.conversations.push({
    id, tenant_id: 'default', owner_id: 'e2e-owner', project_id: null,
    title: 'Rendering conversation', mode: 'chat', classification: 'internal', selected_source: 'auto',
    status: 'active', message_count: 0, created_at: now, updated_at: now,
  });
}

test.describe('Enkstein safe message rendering', () => {
  test('assistant Markdown renders safely with headings, lists, tables, links, and inert raw HTML', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    seedChat(store, 'chat-md');
    await mockTurnStream(page, store, { conversationId: 'chat-md', assistantContent: MARKDOWN });

    await page.goto('/marcellus/chat/chat-md');
    await page.getByPlaceholder('Message Enkstein').fill('render markdown');
    await page.getByRole('button', { name: 'Send' }).click();

    await expect(page.getByRole('heading', { name: 'Deployment plan' })).toBeVisible();
    await expect(page.locator('.rc-md ul li').first()).toHaveText('First governed step');
    await expect(page.locator('.rc-md table th').first()).toHaveText('Stage');

    const link = page.getByRole('link', { name: 'runbook' });
    await expect(link).toHaveAttribute('href', 'https://example.com/runbook');
    await expect(link).toHaveAttribute('rel', /noopener/);
    await expect(link).toHaveAttribute('target', '_blank');

    // Raw HTML is neutralized: skipHtml drops the tag entirely, so no live
    // element or onerror handler is ever created (XSS protection).
    await expect(page.locator('img[src="x"]')).toHaveCount(0);
    await expect(page.locator('[onerror]')).toHaveCount(0);
    await expect(page.getByText('must be inert', { exact: false })).toBeVisible();
  });

  test('long fenced code renders with a language label and an accessible copy control', async ({ page }) => {
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    const store = await mockMarcellusWorkspace(page);
    seedChat(store, 'chat-code');
    await mockTurnStream(page, store, { conversationId: 'chat-code', assistantContent: MARKDOWN });

    await page.goto('/marcellus/chat/chat-code');
    await page.getByPlaceholder('Message Enkstein').fill('render code');
    await page.getByRole('button', { name: 'Send' }).click();

    await expect(page.locator('.rc-code-lang')).toHaveText('PowerShell');
    // The full block is present without truncation, including its terminal line.
    await expect(page.locator('.rc-code-body')).toContainText('Terminal PowerShell line marker 9f3a done');
    // The body scrolls horizontally rather than wrapping long lines.
    await expect(page.locator('.rc-code-body')).toHaveCSS('white-space', 'pre');

    const copy = page.getByRole('button', { name: 'Copy code to clipboard' });
    await copy.click();
    await expect(page.getByRole('button', { name: 'Code copied to clipboard' })).toBeVisible();
    const clipboard = await page.evaluate(() => navigator.clipboard.readText());
    expect(clipboard).toContain('Terminal PowerShell line marker 9f3a done');
  });

  test('a timed-out turn shows a terminal block whose Retry replays without duplicate submission', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    seedChat(store, 'chat-retry');
    const calls = await mockTurnStream(page, store, {
      conversationId: 'chat-retry',
      assistantContent: MARKDOWN,
      outcomes: ['timeout', 'completed'],
    });

    await page.goto('/marcellus/chat/chat-retry');
    await page.getByPlaceholder('Message Enkstein').fill('trigger timeout');
    await page.getByRole('button', { name: 'Send' }).click();

    await expect(page.getByText('Turn timed out')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Continue from the failed turn in the composer' })).toBeVisible();
    expect(calls()).toBe(1);

    await page.getByRole('button', { name: 'Retry the failed turn' }).click();
    await expect(page.getByRole('heading', { name: 'Deployment plan' })).toBeVisible();
    await expect(page.getByText('Turn timed out')).toHaveCount(0);
    // Exactly one additional governed request — the failed turn rolled back, so
    // the retry is a single fresh submission, not a duplicate.
    expect(calls()).toBe(2);
  });

  test('a failed turn Continue control returns the message to the composer and stays mode-isolated', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    seedChat(store, 'chat-continue');
    await mockTurnStream(page, store, { conversationId: 'chat-continue', assistantContent: MARKDOWN, outcomes: ['failed'] });

    await page.goto('/marcellus/chat/chat-continue');
    await page.getByPlaceholder('Message Enkstein').fill('please continue me');
    await page.getByRole('button', { name: 'Send' }).click();

    await expect(page.getByText('Turn failed')).toBeVisible();
    await page.getByRole('button', { name: 'Continue from the failed turn in the composer' }).click();
    await expect(page.getByPlaceholder('Message Enkstein')).toHaveValue('please continue me');

    // Chat stays simple: the Cowork-only project/file panel never appears.
    await expect(page.getByText('Project files')).toHaveCount(0);
  });
});

test.describe('Enkstein Cowork project file panel', () => {
  test('the file panel binds to the active project and refreshes on project switch', async ({ page }) => {
    const store = createWorkspaceStore();
    const now = new Date().toISOString();
    store.projects.push(
      { id: 'proj-a', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Alpha project', description: '', classification: 'internal', default_source: 'auto', status: 'active', created_at: now, updated_at: now },
      { id: 'proj-b', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Beta project', description: '', classification: 'internal', default_source: 'auto', status: 'active', created_at: now, updated_at: now },
    );
    seedArtifacts(store, 'proj-a', ['alpha/only-in-a.py']);
    seedArtifacts(store, 'proj-b', ['beta/only-in-b.py']);
    await mockMarcellusWorkspace(page, store);

    await page.goto('/marcellus/cowork/proj-a');

    // Project A's file panel shows only its own file.
    await expect(page.getByTitle('alpha/only-in-a.py')).toBeVisible();
    await expect(page.getByTitle('beta/only-in-b.py')).toHaveCount(0);

    // Switching the active project via the sidebar selector refreshes the
    // panel to the newly selected project's files, with no stale carryover
    // from the previous project (the artifact-load race this guards against).
    await page.getByLabel('Cowork project').selectOption('proj-b');
    await expect(page.getByTitle('beta/only-in-b.py')).toBeVisible();
    await expect(page.getByTitle('alpha/only-in-a.py')).toHaveCount(0);
  });
});
