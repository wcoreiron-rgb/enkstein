import { expect, test } from './fixtures';
import { createWorkspaceStore, mockMarcellusWorkspace, sse } from './marcellus-workspace-mocks';
import type { WorkspaceStore } from './marcellus-workspace-mocks';

const BRAIN_STATUSES = [
  { brain: 'codex_subscription', kind: 'subscription', available: true, authenticated: true, status: 'ready', detail: 'Ready', models: [] },
  { brain: 'chatgpt_browser', kind: 'browser_session', available: true, authenticated: true, status: 'ready', detail: 'Ready', models: [] },
  { brain: 'gemini_browser', kind: 'browser_session', available: true, authenticated: true, status: 'ready', detail: 'Ready', models: [] },
  { brain: 'claude_browser', kind: 'browser_session', available: false, authenticated: false, status: 'needs_setup', detail: 'Not paired', models: [] },
];

function seedChat(store: WorkspaceStore, id: string) {
  const now = new Date().toISOString();
  store.conversations.push({
    id, tenant_id: 'default', owner_id: 'e2e-owner', project_id: null,
    title: 'Swarm conversation', mode: 'chat', classification: 'internal', selected_source: 'auto',
    status: 'active', message_count: 0, created_at: now, updated_at: now,
  });
}

test.describe('Enkstein custom Brain swarm builder', () => {
  test('picking a mix of browser and subscription Brains submits as a consensus turn with the exact selection', async ({ page }) => {
    const store = createWorkspaceStore();
    seedChat(store, 'chat-swarm');
    await mockMarcellusWorkspace(page, store);
    await page.route('**/api/v1/modelclaw/brains/status**', (route) => route.fulfill({ json: BRAIN_STATUSES }));

    let captured: Record<string, unknown> | null = null;
    await page.route('**/marcellus/workspace/conversations/chat-swarm/turns/stream', async (route) => {
      captured = route.request().postDataJSON();
      const now = new Date().toISOString();
      const body = [
        sse('turn_started', { conversation_id: 'chat-swarm', agent_mode: false }),
        sse('turn_completed', {
          conversation: store.conversations[0],
          user_message: { id: 'm-user', tenant_id: 'default', conversation_id: 'chat-swarm', role: 'user', content: 'hi', classification: 'internal', governance: {}, created_at: now },
          assistant_message: {
            id: 'm-assist', tenant_id: 'default', conversation_id: 'chat-swarm', role: 'assistant',
            content: 'Swarm answer', classification: 'internal', source: 'consensus', provider: null, model: null,
            governance: { outcome: 'allowed', policy_name: 'default', reason: 'ok', risk_score: 3, input_redacted: false, output_redacted: false },
            created_at: now,
          },
          gateway: { status: 'completed', mode: 'chat', governance: {}, votes: [] },
        }),
      ];
      await route.fulfill({ status: 200, contentType: 'text/event-stream', body: body.join('') });
    });

    await page.goto('/marcellus/chat/chat-swarm');
    // Subscription/browser sources load asynchronously after mount; wait for
    // them to actually appear before opening the swarm picker, since
    // selecting the static "Build a Swarm..." option itself does not wait
    // for that unrelated async data to arrive first.
    await expect(page.getByLabel('Brain source').locator('option', { hasText: 'Codex subscription' })).toHaveCount(1);
    await page.getByLabel('Brain source').selectOption('custom_swarm');

    // The picker opens automatically on selecting "Build a Swarm...".
    await expect(page.getByRole('heading', { name: 'Build a Swarm' })).toBeVisible();
    await page.getByRole('checkbox', { name: /Codex subscription/i }).check();
    await page.getByRole('checkbox', { name: /ChatGPT browser session/i }).check();
    await page.getByRole('checkbox', { name: /Gemini browser session/i }).check();
    // An unavailable Brain must not be selectable at all.
    await expect(page.getByRole('checkbox', { name: /Claude browser session/i })).toBeDisabled();
    await expect(page.getByText('3 selected')).toBeVisible();

    await page.getByLabel('Minimum votes required').selectOption('2');
    await page.getByRole('button', { name: 'Use this swarm' }).click();
    await expect(page.getByRole('heading', { name: 'Build a Swarm' })).toHaveCount(0);

    // The toolbar shows the swarm is active and lets it be reopened.
    await expect(page.getByRole('button', { name: '3 Brains' })).toBeVisible();

    await page.getByPlaceholder('Message Enkstein').fill('ask the swarm');
    await page.getByRole('button', { name: 'Send' }).click();
    await expect(page.getByText('Swarm answer')).toBeVisible();

    const payload: Record<string, unknown> = captured ?? (() => { throw new Error('The swarm turn request body was never captured.'); })();
    expect(payload.source).toBe('consensus');
    expect(payload.consensus_sources).toEqual(['codex_subscription', 'chatgpt_browser', 'gemini_browser']);
    expect(payload.minimum_votes).toBe(2);
  });

  test('submitting with an empty swarm is blocked with a clear error instead of silently sending nothing', async ({ page }) => {
    const store = createWorkspaceStore();
    seedChat(store, 'chat-empty-swarm');
    await mockMarcellusWorkspace(page, store);
    await page.route('**/api/v1/modelclaw/brains/status**', (route) => route.fulfill({ json: BRAIN_STATUSES }));

    await page.goto('/marcellus/chat/chat-empty-swarm');
    await page.getByLabel('Brain source').selectOption('custom_swarm');
    await expect(page.getByRole('heading', { name: 'Build a Swarm' })).toBeVisible();
    // Cancelling with nothing picked returns the source to Auto rather than
    // leaving a broken custom_swarm selection active with zero members.
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByLabel('Brain source')).toHaveValue('auto');
  });

  test('reopening the swarm picker preserves the previous selection', async ({ page }) => {
    const store = createWorkspaceStore();
    seedChat(store, 'chat-reopen-swarm');
    await mockMarcellusWorkspace(page, store);
    await page.route('**/api/v1/modelclaw/brains/status**', (route) => route.fulfill({ json: BRAIN_STATUSES }));

    await page.goto('/marcellus/chat/chat-reopen-swarm');
    await expect(page.getByLabel('Brain source').locator('option', { hasText: 'Codex subscription' })).toHaveCount(1);
    await page.getByLabel('Brain source').selectOption('custom_swarm');
    await page.getByRole('checkbox', { name: /Codex subscription/i }).check();
    await page.getByRole('button', { name: 'Use this swarm' }).click();

    await page.getByRole('button', { name: '1 Brain' }).click();
    await expect(page.getByRole('checkbox', { name: /Codex subscription/i })).toBeChecked();
  });
});
