import { expect, test } from './fixtures';
import { mockMarcellusWorkspace, seedArtifacts } from './marcellus-workspace-mocks';

test.describe('Enkstein workspace mode separation', () => {
  test('mode selector switches immediately and keeps the route synchronized', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await page.goto('/marcellus');

    await expect(page).toHaveURL(/\/marcellus\/chat$/);
    await expect(page.getByRole('heading', { name: 'What are we working on?' })).toBeVisible();

    await page.getByTitle('Cowork').click();
    await expect(page).toHaveURL(/\/marcellus\/cowork$/);
    await expect(page.getByRole('heading', { name: 'What are we building?' })).toBeVisible();

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

    await expect(page.getByRole('heading', { name: 'What are we building?' })).toBeVisible();
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

  test('base workspace routes open clean instead of adopting a previous conversation', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    const now = new Date().toISOString();
    store.projects.push({
      id: 'project-canonical', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Canonical Project',
      description: '', kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active',
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
    // The base route stays put: an existing conversation must not be loaded
    // and the URL must not be rewritten to point at it.
    await expect(page).toHaveURL(/\/marcellus\/chat$/);
    await expect(page.getByRole('heading', { name: 'What are we working on?' })).toBeVisible();

    await page.goto('/marcellus/cowork');
    await expect(page).toHaveURL(/\/marcellus\/cowork$/);
    await expect(page.getByRole('heading', { name: 'What are we building?' })).toBeVisible();
    // With no project bound there is nothing for the file panel to show.
    await expect(page.getByTestId('cowork-panel')).toHaveCount(0);

    // Deep links still resolve to the exact conversation they name.
    await page.goto('/marcellus/cowork/project-canonical/cowork-canonical');
    await expect(page).toHaveURL(/\/marcellus\/cowork\/project-canonical\/cowork-canonical$/);
    await expect(page.getByTestId('cowork-panel')).toBeVisible();
  });

  test('switching to a conversation in a different Cowork project shows only that project\'s files', async ({ page }) => {
    // Regression for: opening a conversation belonging to a different
    // project than whatever the sidebar's own project picker last had
    // selected used to leave the previous project's file panel/header
    // showing (and its files still attachable to a new turn), because
    // artifacts were only refreshed in some of the code paths that change
    // the active conversation. The file panel must always reflect the
    // project of whichever conversation is actually open.
    const store = await mockMarcellusWorkspace(page);
    const now = new Date().toISOString();
    store.projects.push(
      {
        id: 'project-alpha', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Alpha Project',
        description: '', kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active',
        created_at: now, updated_at: now,
      },
      {
        id: 'project-beta', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Beta Project',
        description: '', kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active',
        created_at: now, updated_at: now,
      },
    );
    store.conversations.push(
      {
        id: 'cowork-alpha', tenant_id: 'default', owner_id: 'e2e-owner', project_id: 'project-alpha',
        title: 'Alpha Conversation', mode: 'cowork', classification: 'internal', selected_source: 'auto',
        status: 'active', message_count: 0, created_at: now, updated_at: now,
      },
      {
        id: 'cowork-beta', tenant_id: 'default', owner_id: 'e2e-owner', project_id: 'project-beta',
        title: 'Beta Conversation', mode: 'cowork', classification: 'internal', selected_source: 'auto',
        status: 'active', message_count: 0, created_at: now, updated_at: now,
      },
    );
    seedArtifacts(store, 'project-alpha', ['alpha-only-file.py']);
    seedArtifacts(store, 'project-beta', ['beta-only-file.py']);

    await page.goto('/marcellus/cowork/project-alpha/cowork-alpha');
    await expect(page.getByText('alpha-only-file.py')).toBeVisible();
    await expect(page.getByTitle('Alpha Project', { exact: true })).toBeVisible();
    await expect(page.getByText('beta-only-file.py')).toHaveCount(0);

    // Navigate directly to the other project's conversation by URL (e.g. a
    // saved link, browser back/forward, or reopening an archived
    // conversation from a different project) rather than through the
    // sidebar's own project-scoped conversation list, which only ever lists
    // conversations for whichever single project it has selected.
    await page.goto('/marcellus/cowork/project-beta/cowork-beta');
    await expect(page).toHaveURL(/\/marcellus\/cowork\/project-beta\/cowork-beta$/);
    await expect(page.getByText('beta-only-file.py')).toBeVisible();
    await expect(page.getByTitle('Beta Project', { exact: true })).toBeVisible();
    await expect(page.getByText('alpha-only-file.py')).toHaveCount(0);

    // The sidebar's own project dropdown must agree with what's shown.
    await expect(page.getByLabel('Cowork project')).toHaveValue('project-beta');
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
    await expect(page.getByRole('heading', { name: 'What are we building?' })).toBeVisible();

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
    // Cowork opens unfiled, so its prompt reads "Ask about this work" until a
    // project is bound.
    await expect(page.getByPlaceholder('Ask about this work')).toHaveValue('');

    await page.getByTitle('Chat').click();
    // Chat also remounted, so its earlier draft is gone rather than restored.
    await expect(page.getByPlaceholder('Message Enkstein')).toHaveValue('');
  });

  test('creating a project in Cowork immediately scopes the workspace to it', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await page.goto('/marcellus#cowork');
    await expect(page.getByRole('heading', { name: 'What are we building?' })).toBeVisible();

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
      kind: 'cowork',
      classification: 'internal',
      default_source: 'auto',
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });

    await page.goto('/marcellus#cowork');
    // Cowork opens unfiled by default, so the project has to be chosen
    // explicitly before its project-bound surface appears.
    await expect(page.getByRole('heading', { name: 'What are we building?' })).toBeVisible();
    await page.getByLabel('Cowork project').selectOption('project-native');
    await expect(page.getByRole('heading', { name: 'Work with this project' })).toBeVisible();

    await page.evaluate(() => {
      window.dispatchEvent(new CustomEvent('marcellus:native-workspace-selected', {
        detail: { token: 'native-token', name: 'client-repo' },
      }));
    });

    await expect(page.getByText('Local folder: client-repo')).toBeVisible();
    await expect(page.getByText('client-repo', { exact: true })).toBeVisible();
  });

  test('New Project folder pick always creates a fresh project, even when one with the same folder name already exists', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    const now = new Date().toISOString();
    store.projects.push({
      id: 'project-old-client-repo', tenant_id: 'default', owner_id: 'e2e-owner', name: 'client-repo', description: '',
      kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active', created_at: now, updated_at: now,
    });
    store.conversations.push({
      id: 'conversation-old', tenant_id: 'default', owner_id: 'e2e-owner', project_id: 'project-old-client-repo',
      title: 'Old unrelated chat', mode: 'cowork', classification: 'internal', selected_source: 'auto',
      status: 'active', message_count: 0, created_at: now, updated_at: now,
    });

    await page.goto('/marcellus#cowork');
    // No project selected yet -- stub the native picker global the same way
    // the packaged app injects it, so Sidebar's folder-pick button is enabled.
    await page.evaluate(() => {
      (window as unknown as { marcellusNativeWorkspace: { selectFolder: () => void } }).marcellusNativeWorkspace = {
        selectFolder: () => window.dispatchEvent(new CustomEvent('marcellus:native-workspace-selected', {
          detail: { token: 'new-token', name: 'client-repo' },
        })),
      };
    });

    await page.getByLabel('New project').click();
    await page.getByRole('button', { name: 'Pick a local folder instead' }).click();

    // A second, distinct project is created rather than silently reusing
    // "project-old-client-repo" because the folder name happens to match --
    // the old project's unrelated conversation must not appear.
    await expect(page.getByRole('heading', { name: 'Work with this project' })).toBeVisible();
    await expect(page.getByText('Old unrelated chat')).toHaveCount(0);
    const projectOptions = await page.getByLabel('Cowork project').locator('option').allTextContents();
    expect(projectOptions.filter((text) => text === 'client-repo')).toHaveLength(2);
  });

  test('Cowork agent tools use the governed native Codex App Server when a folder is connected', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    const now = new Date().toISOString();
    store.projects.push({
      id: 'project-codex', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Codex Project',
      description: '', kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active',
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
        kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active',
        created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
      },
      {
        id: 'project-b',
        tenant_id: 'default', owner_id: 'e2e-owner', name: 'Project Beta', description: '',
        kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active',
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

  test('Chat has its own separate project/folder picker, distinct from Cowork', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    const now = new Date().toISOString();
    store.projects.push(
      { id: 'chat-folder-a', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Research chats', description: '', kind: 'chat', classification: 'internal', default_source: 'auto', status: 'active', created_at: now, updated_at: now },
      { id: 'cowork-folder-a', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Backend project', description: '', kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active', created_at: now, updated_at: now },
    );

    await page.goto('/marcellus#chat');
    // Chat's own project picker only ever lists Chat-kind folders.
    await expect(page.getByLabel('Chat folder', { exact: true }).locator('option', { hasText: 'Research chats' })).toHaveCount(1);
    const chatOptions = await page.getByLabel('Chat folder', { exact: true }).locator('option').allTextContents();
    expect(chatOptions).toContain('Research chats');
    expect(chatOptions).not.toContain('Backend project');

    await page.getByTitle('Cowork').click();
    // Cowork's own picker only ever lists Cowork-kind projects.
    await expect(page.getByLabel('Cowork project').locator('option', { hasText: 'Backend project' })).toHaveCount(1);
    const coworkOptions = await page.getByLabel('Cowork project').locator('option').allTextContents();
    expect(coworkOptions).toContain('Backend project');
    expect(coworkOptions).not.toContain('Research chats');
  });

  test('creating a Chat folder organizes Chat conversations without requiring one', async ({ page }) => {
    await mockMarcellusWorkspace(page);
    await page.goto('/marcellus#chat');

    // Unlike Cowork, Chat never requires a project to be selected: a fresh
    // Chat conversation can start immediately with none selected.
    await expect(page.getByPlaceholder('Message Enkstein')).toBeVisible();

    await page.getByLabel('New chat folder').click();
    await page.getByPlaceholder('Folder name').fill('Deep research');
    await page.getByLabel('Create project').click();

    await expect(page.getByLabel('Chat folder', { exact: true })).toHaveValue(/.+/);
  });
});
