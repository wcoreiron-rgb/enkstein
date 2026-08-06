import { expect, test } from './fixtures';
import { mockMarcellusWorkspace, seedArtifacts, type WorkspaceStore } from './marcellus-workspace-mocks';

/** Cowork treats the Brain (planning/authoring) and the Executor
 * (commands/tests/verification) as independent. These specs assert the operator
 * can see and choose them separately, that Codex is never presented as
 * required, and that switching projects never mixes one project's files into
 * another's -- including when a slow request for the previous project resolves
 * after the switch. */

type ExecutorPayload = {
  executors: Array<{ executor: string; label: string; available: boolean; reason: string }>;
  selected: string;
  selected_label: string;
  any_available: boolean;
  project_selected?: boolean;
  needs_folder?: boolean;
};

const LOCAL_ONLY: ExecutorPayload = {
  executors: [
    { executor: 'enkstein_local', label: 'Enkstein Local Runtime', available: true, reason: '' },
    { executor: 'codex_app_server', label: 'Codex App Server', available: false, reason: 'Codex is not connected.' },
  ],
  selected: 'enkstein_local',
  selected_label: 'Enkstein Local Runtime',
  any_available: true,
};

const NONE_AVAILABLE: ExecutorPayload = {
  executors: [
    { executor: 'enkstein_local', label: 'Enkstein Local Runtime', available: false, reason: 'The desktop runtime is not connected, so commands cannot run.' },
    { executor: 'codex_app_server', label: 'Codex App Server', available: false, reason: 'Codex is not connected.' },
  ],
  selected: 'unavailable',
  selected_label: 'unavailable',
  any_available: false,
};

/** A real project is open, but no local folder has been approved for it. This
 * is the state that made the picker look broken: every executor reported
 * "unavailable" with no indication that approving a folder is the fix. */
const NEEDS_FOLDER: ExecutorPayload = {
  executors: [
    { executor: 'enkstein_local', label: 'Enkstein Local Runtime', available: false, reason: 'This project has no local folder connected. Use Import folder in the Project files panel to approve one.' },
    { executor: 'codex_app_server', label: 'Codex App Server', available: false, reason: 'This project has no local folder connected. Use Import folder in the Project files panel to approve one.' },
  ],
  selected: 'unavailable',
  selected_label: 'unavailable',
  any_available: false,
  project_selected: true,
  needs_folder: true,
};

async function routeExecutors(page: Parameters<typeof mockMarcellusWorkspace>[0], payload: ExecutorPayload) {
  await page.route('**/api/v1/marcellus/cowork/executors*', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(payload),
  }));
}

function seedProject(store: WorkspaceStore, id: string, name: string) {
  const now = new Date().toISOString();
  store.projects.push({
    id, tenant_id: 'default', owner_id: 'e2e-owner', name, description: '', kind: 'cowork',
    classification: 'internal', default_source: 'auto', status: 'active', created_at: now, updated_at: now,
  });
}

test.describe('Cowork executor independence', () => {
  test('offers an executor choice that is separate from the Brain choice', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await routeExecutors(page, LOCAL_ONLY);
    await page.goto('/marcellus/cowork');

    const executor = page.getByLabel('Executor');
    await expect(executor).toBeVisible();
    // The Brain selector remains its own separate control.
    await expect(page.getByLabel('Brain source')).toBeVisible();

    await expect(executor).toHaveValue('auto');
    await executor.selectOption('enkstein_local');
    await expect(executor).toHaveValue('enkstein_local');
  });

  test('marks a disconnected Codex as unavailable without requiring it', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await routeExecutors(page, LOCAL_ONLY);
    await page.goto('/marcellus/cowork');

    // Poll: the option labels only gain availability once the executor probe lands.
    await expect
      .poll(async () => (await page.getByLabel('Executor').locator('option').allTextContents()).join('|'))
      .toContain('Codex App Server — unavailable');
    const options = await page.getByLabel('Executor').locator('option').allTextContents();
    expect(options.some((text) => text.includes('Enkstein Local Runtime') && text.includes('unavailable'))).toBe(false);
    // Codex being disconnected must never be presented as a hard requirement.
    await expect(page.getByText(/Codex is required/i)).toHaveCount(0);
  });

  test('keeps an explicit executor choice even when it is unavailable', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await routeExecutors(page, NONE_AVAILABLE);
    await page.goto('/marcellus/cowork');

    const executor = page.getByLabel('Executor');
    await executor.selectOption('codex_app_server');
    // No silent reroute to the other executor: the explicit choice stands so the
    // operator can see why verification will not run.
    await expect(executor).toHaveValue('codex_app_server');
  });

  test('remembers the executor preference across a reload', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await routeExecutors(page, LOCAL_ONLY);
    await page.goto('/marcellus/cowork');

    await page.getByLabel('Executor').selectOption('enkstein_local');
    await page.goto('/marcellus/cowork');
    await expect(page.getByLabel('Executor')).toHaveValue('enkstein_local');
  });

  test('a folderless project explains itself and offers the fix', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    seedProject(store, 'project-a', 'Project A');
    await routeExecutors(page, NEEDS_FOLDER);
    await page.goto('/marcellus/cowork');
    await page.getByLabel('Cowork project').selectOption('project-a');

    // The reason must name the remedy, not just report an unavailable executor.
    await expect(page.getByText(/no local folder connected/i)).toBeVisible();
    await expect(page.getByTestId('executor-connect-folder')).toBeVisible();
  });

  test('Auto is marked unavailable when nothing can actually run', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await routeExecutors(page, NEEDS_FOLDER);
    await page.goto('/marcellus/cowork');

    // Auto previously read as a healthy default while nothing could execute.
    await expect
      .poll(async () => (await page.getByLabel('Executor').locator('option').allTextContents()).join('|'))
      .toMatch(/Auto — unavailable/);
  });

  test('does not offer a folder fix when the desktop runtime itself is down', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await routeExecutors(page, NONE_AVAILABLE);
    await page.goto('/marcellus/cowork');

    await expect(page.getByText(/desktop runtime is not connected/i)).toBeVisible();
    // Approving a folder cannot help here, so the affordance must stay hidden.
    await expect(page.getByTestId('executor-connect-folder')).toHaveCount(0);
  });
});

test.describe('Cowork project switching isolation', () => {
  test('project A to project B replaces the file list instead of merging it', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    seedProject(store, 'project-a', 'Project A');
    seedProject(store, 'project-b', 'Project B');
    seedArtifacts(store, 'project-a', ['a-only.ts']);
    seedArtifacts(store, 'project-b', ['b-only.ts']);
    await routeExecutors(page, LOCAL_ONLY);

    await page.goto('/marcellus/cowork');
    const picker = page.getByLabel('Cowork project');
    await picker.selectOption('project-a');
    await expect(page.getByText('a-only.ts')).toBeVisible();

    await picker.selectOption('project-b');
    await expect(page.getByText('b-only.ts')).toBeVisible();
    await expect(page.getByText('a-only.ts')).toHaveCount(0);
  });

  test('project B to an unfiled conversation clears project files', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    seedProject(store, 'project-b', 'Project B');
    seedArtifacts(store, 'project-b', ['b-only.ts']);
    await routeExecutors(page, LOCAL_ONLY);

    await page.goto('/marcellus/cowork');
    const picker = page.getByLabel('Cowork project');
    await picker.selectOption('project-b');
    await expect(page.getByText('b-only.ts')).toBeVisible();

    await picker.selectOption('');
    await expect(page.getByText('b-only.ts')).toHaveCount(0);
  });

  test('project A to a newly created project starts with an empty file list', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    seedProject(store, 'project-a', 'Project A');
    seedProject(store, 'project-fresh', 'Fresh Project');
    seedArtifacts(store, 'project-a', ['a-only.ts']);
    await routeExecutors(page, LOCAL_ONLY);

    await page.goto('/marcellus/cowork');
    const picker = page.getByLabel('Cowork project');
    await picker.selectOption('project-a');
    await expect(page.getByText('a-only.ts')).toBeVisible();

    await picker.selectOption('project-fresh');
    await expect(page.getByText('a-only.ts')).toHaveCount(0);
  });

  test('a slow project A response resolving after switching to B does not repopulate A files', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    seedProject(store, 'project-a', 'Project A');
    seedProject(store, 'project-b', 'Project B');
    seedArtifacts(store, 'project-a', ['a-only.ts']);
    seedArtifacts(store, 'project-b', ['b-only.ts']);
    await routeExecutors(page, LOCAL_ONLY);

    // Delay only project A's artifact fetch so it lands after the switch to B.
    await page.route('**/marcellus/workspace/projects/project-a/artifacts*', async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      await route.fallback();
    });

    await page.goto('/marcellus/cowork');
    const picker = page.getByLabel('Cowork project');
    await picker.selectOption('project-a');
    await picker.selectOption('project-b');

    await expect(page.getByText('b-only.ts')).toBeVisible();
    // Wait past the delayed A response, then assert it was discarded as stale.
    await page.waitForTimeout(2000);
    await expect(page.getByText('a-only.ts')).toHaveCount(0);
    await expect(page.getByText('b-only.ts')).toBeVisible();
  });
});
