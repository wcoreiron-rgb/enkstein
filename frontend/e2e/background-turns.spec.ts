import { expect, test } from './fixtures';
import { mockMarcellusWorkspace, mockTurnStream } from './marcellus-workspace-mocks';
import type { WorkspaceStore } from './marcellus-workspace-mocks';

/** A governed turn used to be owned by the workspace page component, so
 *  opening another conversation unmounted it and abandoned the request. These
 *  tests pin the turn surviving navigation, the tray reporting it, and the
 *  finished reply still being there when the operator comes back. */

function seedChat(store: WorkspaceStore, id: string, title: string) {
  const now = new Date().toISOString();
  store.conversations.push({
    id, tenant_id: 'default', owner_id: 'e2e-owner', project_id: null,
    title, mode: 'chat', classification: 'internal', selected_source: 'auto',
    status: 'active', message_count: 0, created_at: now, updated_at: now,
  } as never);
}

test.describe('Enkstein background turns', () => {
  test('a turn keeps running after navigating away and its reply is waiting on return', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    seedChat(store, 'chat-background', 'Long running turn');
    seedChat(store, 'chat-other', 'Somewhere else');

    // Hold the stream open long enough to navigate mid-turn, which is the
    // exact window where the old code lost the request.
    let releaseTurn!: () => void;
    const held = new Promise<void>((resolve) => { releaseTurn = resolve; });
    const calls = await mockTurnStream(page, store, {
      conversationId: 'chat-background',
      assistantContent: 'The reply that arrived while you were away.',
      hold: () => held,
    });

    await page.goto('/marcellus/chat/chat-background');
    await page.getByPlaceholder('Message Enkstein').fill('start something slow');
    await page.getByRole('button', { name: 'Send' }).click();

    // The tray reports the turn, and it is reachable from anywhere.
    const tray = page.getByTestId('background-turn-tray');
    await expect(tray).toBeVisible();
    await expect(tray.getByText('Long running turn')).toBeVisible();

    // Leave the conversation while the turn is still in flight, the way the
    // app actually does it: a client-side switch from the sidebar, which
    // unmounts the workspace instance without reloading the document.
    await page.getByRole('button', { name: /Somewhere else/ }).first().click();
    await expect(page.getByTestId('background-turn-tray').getByText('Long running turn')).toBeVisible();
    // The mode button carries a live marker for its own pending work.
    await expect(page.getByTestId('mode-activity-chat')).toHaveAttribute('data-activity', 'running');

    releaseTurn();

    // The turn settles while the operator is elsewhere, and says so.
    await expect(page.getByTestId('background-turn-tray').getByText('Reply ready')).toBeVisible();
    await expect(page.getByTestId('mode-activity-chat')).toHaveAttribute('data-activity', 'unread');

    // The tray entry is itself the way back to the finished turn.
    await page.getByTestId('background-turn-tray').getByRole('link', { name: /Long running turn/ }).click();
    // Longer than the default: this is a client-side route change into the
    // deep-linked conversation page, which the dev server may still be
    // compiling when the suite runs several specs in parallel.
    await expect(page.getByText('The reply that arrived while you were away.')).toBeVisible({ timeout: 30_000 });
    await expect(page.getByTestId('mode-activity-chat')).toHaveCount(0);

    // Exactly one governed submission: navigation must not have replayed it.
    expect(calls()).toBe(1);
  });

  test('the tray is absent when nothing is running', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    seedChat(store, 'chat-idle', 'Idle conversation');
    await page.goto('/marcellus/chat/chat-idle');
    await expect(page.getByPlaceholder('Message Enkstein')).toBeVisible();
    await expect(page.getByTestId('background-turn-tray')).toHaveCount(0);
    await expect(page.getByTestId('mode-activity-chat')).toHaveCount(0);
  });

  test('stopping a background turn removes it from the tray', async ({ page }) => {
    const store = await mockMarcellusWorkspace(page);
    seedChat(store, 'chat-stoppable', 'Stoppable turn');
    let releaseTurn!: () => void;
    const held = new Promise<void>((resolve) => { releaseTurn = resolve; });
    await mockTurnStream(page, store, {
      conversationId: 'chat-stoppable',
      assistantContent: 'Never seen.',
      hold: () => held,
    });

    await page.goto('/marcellus/chat/chat-stoppable');
    await page.getByPlaceholder('Message Enkstein').fill('start then stop');
    await page.getByRole('button', { name: 'Send' }).click();

    const tray = page.getByTestId('background-turn-tray');
    await expect(tray).toBeVisible();
    await tray.getByRole('button', { name: /Stop the running turn/ }).click();
    await expect(page.getByTestId('background-turn-tray')).toHaveCount(0);
    releaseTurn();
  });
});
