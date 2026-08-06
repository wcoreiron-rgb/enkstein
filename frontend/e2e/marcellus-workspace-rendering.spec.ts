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

  test('completed Cowork turns retain an expandable, content-free file change ledger', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    seedChat(store, 'chat-file-ledger');
    await mockTurnStream(page, store, {
      conversationId: 'chat-file-ledger',
      assistantContent: 'Implemented the governed workspace update.',
      assistantGovernance: {
        file_changes: [
          { path: 'src/app.ts', operation: 'create', outcome: 'applied' },
          { path: 'legacy/debug.ts', operation: 'delete', outcome: 'skipped' },
        ],
      },
    });

    await page.goto('/marcellus/chat/chat-file-ledger');
    await page.getByPlaceholder('Message Enkstein').fill('apply the files');
    await page.getByRole('button', { name: 'Send' }).click();

    await page.getByText('Files changed · 2 files').click();
    await expect(page.getByText('src/app.ts')).toBeVisible();
    await expect(page.getByText('create', { exact: true })).toBeVisible();
    await expect(page.getByText('applied', { exact: true })).toBeVisible();
    await expect(page.getByText('legacy/debug.ts')).toBeVisible();
    await expect(page.getByText('skipped', { exact: true })).toBeVisible();
  });

  test('a multi-Brain turn shows every Brain answer as its own readable card', async ({ page }) => {
    // A swarm turn picks one Brain's answer as the reply. The other Brains'
    // answers used to be discarded entirely, leaving only latency numbers, so
    // the user could not see what the rest of their swarm actually said.
    const store = await mockMarcellusWorkspace(page);
    seedChat(store, 'chat-brains');
    await mockTurnStream(page, store, {
      conversationId: 'chat-brains',
      assistantContent: 'Claude picked this answer.',
      brainAnswers: [
        { source: 'profile:ollama_local_fallback', model: 'regent-aegis:bc', latency_ms: 20491, primary: false, content: 'The local model said something different.' },
        { source: 'chatgpt_browser', model: 'browser-selected', latency_ms: 35059, primary: false, content: 'ChatGPT had its own take.' },
        { source: 'claude_subscription', model: 'subscription-default', latency_ms: 22677, primary: true, content: 'Claude picked this answer.' },
      ],
    });

    await page.goto('/marcellus/chat/chat-brains');
    await page.getByPlaceholder('Message Enkstein').fill('ask my swarm');
    await page.getByRole('button', { name: 'Send' }).click();

    await expect(page.getByText('3 Brains answered.', { exact: false })).toBeVisible();
    await expect(page.getByText('used as the reply')).toBeVisible();

    // A discarded answer is hidden until opened, then fully readable.
    await expect(page.getByText('ChatGPT had its own take.')).toHaveCount(0);
    await page.getByRole('button', { name: /chatgpt_browser/ }).click();
    await expect(page.getByText('ChatGPT had its own take.')).toBeVisible();

    // Cards open one at a time, so a long answer never buries the others.
    await page.getByRole('button', { name: /ollama_local_fallback/ }).click();
    await expect(page.getByText('The local model said something different.')).toBeVisible();
    await expect(page.getByText('ChatGPT had its own take.')).toHaveCount(0);
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

  test('the first message on a brand-new conversation renders its reply', async ({ page }) => {
    // Regression test for a race that made every "first message in a new
    // conversation" turn silently disappear, on every engine and every
    // swarm mode: opening a mode without a conversation ID and sending a
    // message creates the conversation, then used to push the URL to
    // /marcellus/chat/{id} immediately. That path resolves to a different
    // Next.js page file than plain /marcellus/chat, so the push unmounted
    // this whole component mid-stream -- the backend still completed the
    // turn and persisted the reply, but every setMessages/setActive call
    // below fired against an already-unmounted instance, so nothing ever
    // painted. The fix defers navigation until the turn settles.
    const store = await mockMarcellusWorkspace(page);
    // Resolved once the create-conversation POST responds. Awaited before
    // the turns/stream mock reads it, rather than raced via a bare event
    // listener -- the stream request can fire before an async `.then()`
    // chain attached to the 'request' event has resolved.
    let resolveConversationId!: (id: string) => void;
    const conversationIdPromise = new Promise<string>((resolve) => { resolveConversationId = resolve; });

    // The conversation ID doesn't exist until the create call responds, so
    // the turn-stream mock can't be pre-registered against a fixed ID the
    // way seeded-conversation tests do. Match on the URL shape instead and
    // resolve the ID from whatever POST /conversations actually returned.
    await page.route('**/marcellus/workspace/conversations/*/turns/stream', async (route) => {
      const now = new Date().toISOString();
      const conversationId = await conversationIdPromise;
      // A real governed turn takes real network/inference time. The race this
      // guards against only manifests when the client-side route swap (Next
      // resolving/mounting the [conversationId] page file) has a chance to
      // actually happen before the stream settles -- an instantly-resolved
      // mock can finish in the same tick the old code's immediate
      // navigateToConversation() call kicked off, before React ever unmounts
      // this instance, which is why an undelayed version of this test passed
      // even against the pre-fix code.
      await new Promise((resolve) => setTimeout(resolve, 400));
      const userMessage = {
        id: 'msg-user-1', tenant_id: 'default', conversation_id: conversationId,
        role: 'user', content: 'first message ever', classification: 'internal', governance: {}, created_at: now,
      };
      const assistantMessage = {
        id: 'msg-assistant-1', tenant_id: 'default', conversation_id: conversationId,
        role: 'assistant', content: 'The reply to the very first message.', classification: 'internal',
        source: 'auto', provider: 'test-provider', model: 'test-model',
        governance: {
          outcome: 'allowed', policy_name: 'default', reason: 'ok', risk_score: 3,
          input_redacted: false, output_redacted: false, confidence: 0.92,
          runtime_group: 'hybrid', latency_ms: 812, votes: [], context_manifest: null,
        },
        created_at: now,
      };
      const conversation = store.conversations.find((item) => item.id === conversationId) || {
        id: conversationId, tenant_id: 'default', owner_id: 'e2e-owner', project_id: null,
        title: 'New conversation', mode: 'chat', classification: 'internal', selected_source: 'auto',
        status: 'active', message_count: 2, created_at: now, updated_at: now,
      };
      // Mirrors real backend persistence -- see the note on WorkspaceStore
      // ['messages']. Without this, the app's own re-fetch after the URL
      // catches up (correct, real behavior) reads back an empty
      // conversation, which looks identical to the actual regression this
      // test guards against.
      store.messages[conversationId] = [userMessage, assistantMessage];
      const body = [
        `event: turn_started\ndata: ${JSON.stringify({ conversation_id: conversationId, agent_mode: false })}\n\n`,
        `event: response_delta\ndata: ${JSON.stringify({ delta: 'The reply' })}\n\n`,
        `event: turn_completed\ndata: ${JSON.stringify({
          conversation, user_message: userMessage, assistant_message: assistantMessage,
          gateway: { status: 'ok', mode: 'chat', governance: {}, votes: [] },
        })}\n\n`,
      ].join('');
      await route.fulfill({ status: 200, contentType: 'text/event-stream', body });
    });
    page.on('response', (response) => {
      const request = response.request();
      if (request.method() === 'POST' && /\/conversations$/.test(request.url())) {
        response.json().then((created) => {
          if (created?.id) resolveConversationId(created.id);
        }).catch(() => undefined);
      }
    });

    await page.goto('/marcellus/chat');
    await page.getByPlaceholder('Message Enkstein').fill('first message ever');

    const urlBeforeSend = page.url();
    await page.getByRole('button', { name: 'Send' }).click();

    // Checked while the mock's 400ms delay is still in flight -- this is the
    // exact window where the old code's immediate navigateToConversation()
    // call would have already pushed a URL to a different Next.js page
    // file, unmounting this instance before the turn even resolved.
    await page.waitForTimeout(150);
    expect(page.url()).toBe(urlBeforeSend);

    await expect(page.getByText('The reply to the very first message.')).toBeVisible();

    // Now that the turn has settled, the URL catches up to the new
    // conversation -- confirming navigation was deferred, not lost.
    const conversationId = await conversationIdPromise;
    await expect.poll(() => page.url()).toContain(conversationId);
  });
});

test.describe('Enkstein Cowork project file panel', () => {
  test('the file panel binds to the active project and refreshes on project switch', async ({ page }) => {
    const store = createWorkspaceStore();
    const now = new Date().toISOString();
    store.projects.push(
      { id: 'proj-a', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Alpha project', description: '', kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active', created_at: now, updated_at: now },
      { id: 'proj-b', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Beta project', description: '', kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active', created_at: now, updated_at: now },
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

test.describe('Enkstein Cowork VS Code-style folder tree', () => {
  test('files group under real, independently collapsible folder nodes', async ({ page }) => {
    const store = createWorkspaceStore();
    const now = new Date().toISOString();
    store.projects.push({
      id: 'proj-tree', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Tree project', description: '',
      kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active', created_at: now, updated_at: now,
    });
    seedArtifacts(store, 'proj-tree', [
      'src/app/main.py',
      'src/app/utils.py',
      'src/lib/helpers.py',
      'README.md',
    ]);
    await mockMarcellusWorkspace(page, store);

    await page.goto('/marcellus/cowork/proj-tree');

    // Folders render as their own named nodes, not just indentation, and
    // start expanded so every file is initially visible.
    const srcFolder = page.getByRole('button', { name: /Collapse src folder/i });
    await expect(srcFolder).toBeVisible();
    await expect(page.getByRole('button', { name: /Collapse app folder/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Collapse lib folder/i })).toBeVisible();
    await expect(page.getByTitle('src/app/main.py')).toBeVisible();
    await expect(page.getByTitle('src/lib/helpers.py')).toBeVisible();
    await expect(page.getByTitle('README.md')).toBeVisible();

    // Collapsing the top-level "src" folder hides everything nested beneath
    // it, including the "app" and "lib" subfolders and their files, while
    // leaving unrelated top-level files (README.md) visible.
    await srcFolder.click();
    await expect(page.getByTitle('src/app/main.py')).toHaveCount(0);
    await expect(page.getByTitle('src/lib/helpers.py')).toHaveCount(0);
    await expect(page.getByRole('button', { name: /Collapse app folder/i })).toHaveCount(0);
    await expect(page.getByTitle('README.md')).toBeVisible();

    // Re-expanding restores the nested contents.
    await page.getByRole('button', { name: /Expand src folder/i }).click();
    await expect(page.getByTitle('src/app/main.py')).toBeVisible();
  });

  test('switching Cowork projects shows only that project\'s own folder tree', async ({ page }) => {
    const store = createWorkspaceStore();
    const now = new Date().toISOString();
    store.projects.push(
      { id: 'proj-x', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Project X', description: '', kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active', created_at: now, updated_at: now },
      { id: 'proj-y', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Project Y', description: '', kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active', created_at: now, updated_at: now },
    );
    seedArtifacts(store, 'proj-x', ['backend/api/routes.py', 'backend/api/schemas.py']);
    seedArtifacts(store, 'proj-y', ['frontend/components/App.tsx']);
    await mockMarcellusWorkspace(page, store);

    await page.goto('/marcellus/cowork/proj-x');
    await expect(page.getByRole('button', { name: /Collapse backend folder/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Collapse api folder/i })).toBeVisible();
    await expect(page.getByTitle('backend/api/routes.py')).toBeVisible();
    await expect(page.getByRole('button', { name: /frontend folder/i })).toHaveCount(0);

    await page.getByLabel('Cowork project').selectOption('proj-y');
    await expect(page.getByRole('button', { name: /Collapse frontend folder/i })).toBeVisible();
    await expect(page.getByTitle('frontend/components/App.tsx')).toBeVisible();
    await expect(page.getByRole('button', { name: /backend folder/i })).toHaveCount(0);
    await expect(page.getByTitle('backend/api/routes.py')).toHaveCount(0);
  });
});

test.describe('Enkstein message and chat copy', () => {
  test('copying a single assistant message puts exactly that message on the clipboard', async ({ page }) => {
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    const store = await mockMarcellusWorkspace(page);
    seedChat(store, 'chat-copy-message');
    await mockTurnStream(page, store, { conversationId: 'chat-copy-message', assistantContent: 'Here is the answer you asked for.' });

    await page.goto('/marcellus/chat/chat-copy-message');
    await page.getByPlaceholder('Message Enkstein').fill('ask a question');
    await page.getByRole('button', { name: 'Send' }).click();
    await expect(page.getByText('Here is the answer you asked for.')).toBeVisible();

    // The per-message copy control only becomes visible on hover (matching
    // the existing "Branch from here" control's convention), so hover the
    // message before interacting with it, the same as a real user would.
    await page.getByText('Here is the answer you asked for.').hover();
    await page.getByRole('button', { name: 'Copy message to clipboard' }).click();
    await expect(page.getByRole('button', { name: 'Message copied to clipboard' })).toBeVisible();
    const clipboard = await page.evaluate(() => navigator.clipboard.readText());
    expect(clipboard).toBe('Here is the answer you asked for.');
  });

  test('copying the whole chat includes every turn labeled by role, in order', async ({ page }) => {
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    const store = await mockMarcellusWorkspace(page);
    seedChat(store, 'chat-copy-all');
    await mockTurnStream(page, store, { conversationId: 'chat-copy-all', assistantContent: 'First governed answer.' });

    await page.goto('/marcellus/chat/chat-copy-all');
    await page.getByPlaceholder('Message Enkstein').fill('first question');
    await page.getByRole('button', { name: 'Send' }).click();
    await expect(page.getByText('First governed answer.')).toBeVisible();

    await page.getByRole('button', { name: 'Copy whole chat to clipboard' }).click();
    await expect(page.getByRole('button', { name: 'Whole chat copied to clipboard' })).toBeVisible();
    const clipboard = await page.evaluate(() => navigator.clipboard.readText());
    // mockTurnStream always persists a fixed 'user prompt' user message
    // regardless of what was typed, so assert against that real persisted
    // content rather than the composer text.
    expect(clipboard).toContain('user prompt');
    expect(clipboard).toContain('First governed answer.');
    expect(clipboard.indexOf('user prompt')).toBeLessThan(clipboard.indexOf('First governed answer.'));
    expect(clipboard).toContain('You:');
    expect(clipboard).toContain('Enkstein:');
  });
});

test.describe('Enkstein Cowork resizable review panel', () => {
  test('panel can be widened by drag and by the maximize toggle, and the width persists', async ({ page }) => {
    const store = createWorkspaceStore();
    const now = new Date().toISOString();
    store.projects.push({
      id: 'proj-resize', tenant_id: 'default', owner_id: 'e2e-owner', name: 'Resize project', description: '',
      kind: 'cowork', classification: 'internal', default_source: 'auto', status: 'active', created_at: now, updated_at: now,
    });
    seedArtifacts(store, 'proj-resize', ['scripts/deploy.ps1']);
    await mockMarcellusWorkspace(page, store);

    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/marcellus/cowork/proj-resize');

    const panel = page.getByTestId('cowork-panel');
    await expect(panel).toBeVisible();
    const initial = Number(await panel.getAttribute('data-panel-width'));

    // Dragging the separator left widens the panel so long scripts are readable
    // before approval.
    const resizer = page.getByTestId('cowork-panel-resizer');
    const box = await resizer.boundingBox();
    if (!box) throw new Error('resizer has no bounding box');
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await page.mouse.move(box.x - 240, box.y + box.height / 2, { steps: 8 });
    await page.mouse.up();

    const widened = Number(await panel.getAttribute('data-panel-width'));
    expect(widened).toBeGreaterThan(initial);

    // The chosen width survives a reload.
    await page.reload();
    await expect(page.getByTestId('cowork-panel')).toHaveAttribute('data-panel-width', String(widened));

    // The maximize toggle expands further and then restores.
    await page.getByTestId('cowork-panel-maximize').click();
    const maximized = Number(await page.getByTestId('cowork-panel').getAttribute('data-panel-width'));
    expect(maximized).toBeGreaterThanOrEqual(widened);
    await page.getByTestId('cowork-panel-maximize').click();
    await expect(page.getByTestId('cowork-panel')).toHaveAttribute('data-panel-width', String(widened));
  });
});
