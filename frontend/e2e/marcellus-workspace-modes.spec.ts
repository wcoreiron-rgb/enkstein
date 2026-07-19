import { expect, test } from './fixtures';
import { mockMarcellusWorkspace } from './marcellus-workspace-mocks';

test.describe('Enkstein workspace mode separation', () => {
  test('mode selector switches immediately and keeps the route synchronized', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await page.goto('/marcellus');

    await expect(page).toHaveURL(/\/marcellus\/chat$/);
    await expect(page.getByRole('heading', { name: 'What are we working on?' })).toBeVisible();

    await page.getByTitle('Cowork').click();
    await expect(page).toHaveURL(/\/marcellus\/cowork$/);
    await expect(page.getByRole('heading', { name: 'Create or select a project' })).toBeVisible();

    await page.getByTitle('Security').click();
    await expect(page).toHaveURL(/\/marcellus\/security$/);
    await expect(page.getByRole('link', { name: 'Control Center' })).toBeVisible();

    await page.getByTitle('Chat').click();
    await expect(page).toHaveURL(/\/marcellus\/chat$/);
    await expect(page.getByRole('heading', { name: 'What are we working on?' })).toBeVisible();
  });

  test('a hash deep link opens directly into the requested workspace', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await page.goto('/marcellus#cowork');

    await expect(page.getByRole('heading', { name: 'Create or select a project' })).toBeVisible();
    await expect(page.getByLabel('Cowork project')).toBeVisible();
  });

  test('workspace selection survives a reload with no hash present', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await page.goto('/marcellus');
    await page.getByTitle('Security').click();
    await expect(page).toHaveURL(/\/marcellus\/security$/);

    await page.goto('/marcellus');
    await expect(page).toHaveURL(/\/marcellus\/security$/);
    await expect(page.getByRole('link', { name: 'Control Center' })).toBeVisible();
  });

  test('base conversation workspaces canonicalize remembered or default conversations with replace', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    const now = new Date().toISOString();
    store.projects.push({
      id: 'project-canonical', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Canonical Project',
      description: '', classification: 'internal', default_source: 'auto', status: 'active',
      created_at: now, updated_at: now,
    });
    store.conversations.push(
      {
        id: 'chat-canonical', tenant_id: 'default', owner_id: 'e2e-owner', project_id: null,
        title: 'Canonical Chat', mode: 'chat', classification: 'internal', selected_source: 'auto',
        status: 'active', message_count: 0, created_at: now, updated_at: now,
      },
      {
        id: 'cowork-canonical', tenant_id: 'default', owner_id: 'e2e-owner', project_id: 'project-canonical',
        title: 'Canonical Cowork', mode: 'cowork', classification: 'internal', selected_source: 'auto',
        status: 'active', message_count: 0, created_at: now, updated_at: now,
      },
    );

    await page.goto('/marcellus/chat');
    await expect(page).toHaveURL(/\/marcellus\/chat\/chat-canonical$/);
    await page.goto('/marcellus/cowork');
    await expect(page).toHaveURL(/\/marcellus\/cowork\/project-canonical\/cowork-canonical$/);
  });

  test('back and forward navigation stay synchronized with the visible workspace', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await page.goto('/marcellus#chat');
    await page.getByTitle('Cowork').click();
    await expect(page).toHaveURL(/\/marcellus\/cowork$/);
    await page.getByTitle('Security').click();
    await expect(page).toHaveURL(/\/marcellus\/security$/);

    await page.goBack();
    await expect(page).toHaveURL(/\/marcellus\/cowork$/);
    await expect(page.getByRole('heading', { name: 'Create or select a project' })).toBeVisible();

    await page.goBack();
    await expect(page).toHaveURL(/\/marcellus\/chat$/);
    await expect(page.getByRole('heading', { name: 'What are we working on?' })).toBeVisible();

    await page.goForward();
    await expect(page).toHaveURL(/\/marcellus\/cowork$/);
  });

  test('chat and cowork workspaces do not leak draft state between each other', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await page.goto('/marcellus#chat');
    await page.getByPlaceholder('Message Enkstein').fill('Unsent chat-only draft');

    await page.getByTitle('Cowork').click();
    // Cowork remounts as its own AIWorkspace instance (key={mode}) with its
    // own draft state, so its prompt is present but starts empty — it must
    // not inherit Chat's unsent text.
    await expect(page.getByPlaceholder('Ask about this project')).toHaveValue('');

    await page.getByTitle('Chat').click();
    // Chat also remounted, so its earlier draft is gone rather than restored.
    await expect(page.getByPlaceholder('Message Enkstein')).toHaveValue('');
  });

  test('creating a project in Cowork immediately scopes the workspace to it', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await page.goto('/marcellus#cowork');
    await expect(page.getByRole('heading', { name: 'Create or select a project' })).toBeVisible();

    await page.getByLabel('New project').click();
    await page.getByPlaceholder('Project name').fill('Perimeter Rebuild');
    await page.getByLabel('Create project').click();

    await expect(page.getByLabel('Cowork project')).toHaveValue(/.+/);
    await expect(page.getByRole('heading', { name: 'Work with this project' })).toBeVisible();
  });

  test('selecting a native folder immediately shows the synchronized folder name', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    store.projects.push({
      id: 'project-native',
      tenant_id: 'default',
      owner_id: 'e2e-owner',
      name: 'Native Folder Project',
      description: '',
      classification: 'internal',
      default_source: 'auto',
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });

    await page.goto('/marcellus#cowork');
    await expect(page.getByRole('heading', { name: 'Work with this project' })).toBeVisible();

    await page.evaluate(() => {
      window.dispatchEvent(new CustomEvent('marcellus:native-workspace-selected', {
        detail: { token: 'native-token', name: 'client-repo' },
      }));
    });

    await expect(page.getByText('Local folder: client-repo')).toBeVisible();
    await expect(page.getByText('client-repo', { exact: true })).toBeVisible();
  });

  test('Cowork agent tools use the governed native Codex App Server when a folder is connected', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    const now = new Date().toISOString();
    store.projects.push({
      id: 'project-codex', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Codex Project',
      description: '', classification: 'internal', default_source: 'auto', status: 'active',
      created_at: now, updated_at: now,
    });
    store.conversations.push({
      id: 'conversation-codex', tenant_id: 'default', owner_id: 'e2e-owner', project_id: 'project-codex',
      title: 'Native agent task', mode: 'cowork', classification: 'internal', selected_source: 'auto',
      status: 'active', message_count: 0, created_at: now, updated_at: now,
    });
    store.nativeWorkspace['project-codex'] = { connected: true, name: 'native-repo', file_count: 4, synced_files: 4 };

    await page.goto('/marcellus/cowork/project-codex/conversation-codex');
    await expect(page.getByText('Local folder: native-repo')).toBeVisible();
    await page.getByPlaceholder('Ask about this project').fill('Inspect the project safely');
    await page.getByRole('button', { name: 'Send' }).click();

    await expect(page.getByText('Native Codex result')).toBeVisible();
    await expect(page.getByText(/Codex subscription CLI · native App Server/)).toBeVisible();
  });

  test('conversation create, rename, and archive apply immediately', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await page.goto('/marcellus#chat');

    await page.getByLabel('New conversation').click();
    await expect(page.getByRole('heading', { name: 'New conversation' })).toBeVisible();

    await page.getByLabel('Rename conversation').click();
    const renameInput = page.getByLabel('Conversation title');
    await renameInput.fill('Q3 Perimeter Review');
    await page.getByRole('button', { name: 'Rename', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Q3 Perimeter Review' })).toBeVisible();

    await page.getByLabel('Archive conversation').click();
    await page.getByRole('button', { name: 'Archive', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'What are we working on?' })).toBeVisible();
  });

  test('moving a Cowork conversation between projects applies immediately', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    store.projects.push(
      {
        id: 'project-a',
        tenant_id: 'default', owner_id: 'e2e-owner', name: 'Project Alpha', description: '',
        classification: 'internal', default_source: 'auto', status: 'active',
        created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
      },
      {
        id: 'project-b',
        tenant_id: 'default', owner_id: 'e2e-owner', name: 'Project Beta', description: '',
        classification: 'internal', default_source: 'auto', status: 'active',
        created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
      },
    );
    store.conversations.push({
      id: 'conversation-move',
      tenant_id: 'default', owner_id: 'e2e-owner', project_id: 'project-a',
      title: 'Alpha kickoff', mode: 'cowork', classification: 'internal', selected_source: 'auto',
      status: 'active', message_count: 0,
      created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    });

    await page.goto('/marcellus#cowork');
    await page.getByLabel('Cowork project').selectOption('project-a');
    await expect(page.getByRole('heading', { name: 'Alpha kickoff' })).toBeVisible();

    await page.getByLabel('Move conversation to project').click();
    await page.getByLabel('Destination project').selectOption('project-b');
    await page.getByRole('button', { name: 'Move', exact: true }).click();

    await expect(page.getByLabel('Cowork project')).toHaveValue('project-b');
    await expect(page.getByRole('heading', { name: 'Alpha kickoff' })).toBeVisible();
  });
});
