import path from 'node:path';
import { expect, test, type Page } from '@playwright/test';

const CONTENT_SCRIPT = path.resolve(process.cwd(), '../browser-extension/content.js');
const BACKGROUND_SCRIPT = path.resolve(process.cwd(), '../browser-extension/background.js');

function installRuntimeStub() {
  const runtime = {
    listener: null as null | ((message: unknown, sender: unknown, callback: (value: unknown) => void) => boolean),
    onMessage: {
      addListener(listener: typeof runtime.listener) {
        runtime.listener = listener;
      },
    },
    sendMessage() {},
  };
  Object.defineProperty(window, 'chrome', { value: { runtime }, configurable: true });
  Object.defineProperty(window, '__enksteinRuntime', { value: runtime, configurable: true });
}

async function send(page: Page, message: Record<string, unknown>) {
  return page.evaluate((msg) => {
    const runtime = (window as unknown as { __enksteinRuntime: { listener: Function } }).__enksteinRuntime;
    return new Promise((resolve) => runtime.listener(msg, {}, resolve));
  }, message);
}

async function observeUntil(page: Page, taskId: string, wantState: string, attempts = 60) {
  for (let i = 0; i < attempts; i += 1) {
    const observation = await send(page, { type: 'marcellus-observe', task_id: taskId }) as { state: string; response?: string };
    if (observation.state === wantState) return observation;
    await page.waitForTimeout(75);
  }
  throw new Error(`Task ${taskId} never reached state ${wantState}`);
}

const CHATGPT_MULTI_TURN_BODY = `<!doctype html><html><body>
  <div id="prompt-textarea" contenteditable="true" style="width:500px;height:120px"></div>
  <button data-testid="send-button" aria-label="Send prompt" disabled>Send</button>
  <script>
    window.sendClicks = 0;
    const editor = document.querySelector('#prompt-textarea');
    const send = document.querySelector('[data-testid="send-button"]');
    editor.addEventListener('input', () => { send.disabled = !editor.innerText.trim(); });
    send.addEventListener('click', () => {
      window.sendClicks += 1;
      const submitted = editor.innerText;
      editor.textContent = '';
      send.disabled = true;
      const answer = document.createElement('div');
      answer.dataset.messageAuthorRole = 'assistant';
      answer.textContent = 'Turn ' + window.sendClicks + ' response for: ' + submitted;
      document.body.appendChild(answer);
    });
  </script>
</body></html>`;

const GEMINI_MULTI_TURN_BODY = `<!doctype html><html><body>
  <rich-textarea><div contenteditable="true" style="width:500px;height:120px;white-space:pre-wrap"></div></rich-textarea>
  <button aria-label="Send message" disabled>Send</button>
  <script>
    window.sendClicks = 0;
    const editor = document.querySelector('[contenteditable="true"]');
    const send = document.querySelector('button');
    document.execCommand = (command, _ui, value) => {
      if (command === 'delete') editor.textContent = '';
      if (command === 'insertText') editor.textContent += String(value);
      editor.dispatchEvent(new InputEvent('input', { bubbles: true }));
      return true;
    };
    editor.addEventListener('input', () => { send.disabled = !editor.innerText.trim(); });
    send.addEventListener('click', () => {
      window.sendClicks += 1;
      const submitted = editor.innerText;
      editor.textContent = '';
      send.disabled = true;
      const response = document.createElement('model-response');
      response.innerHTML = '<div class="markdown">Turn ' + window.sendClicks + ' response for: ' + submitted + '</div>';
      document.body.appendChild(response);
    });
  </script>
</body></html>`;

test('browser companion submits and observes five sequential ChatGPT turns', async ({ page }) => {
  await page.addInitScript(installRuntimeStub);
  await page.route('https://chatgpt.com/**', async (route) => {
    await route.fulfill({ status: 200, contentType: 'text/html', body: CHATGPT_MULTI_TURN_BODY });
  });
  await page.goto('https://chatgpt.com/');
  await page.addScriptTag({ path: CONTENT_SCRIPT });

  for (let turn = 1; turn <= 5; turn += 1) {
    const taskId = `chatgpt-turn-${turn}`;
    const submitResult = await send(page, {
      type: 'marcellus-submit',
      task: { provider: 'chatgpt', task_id: taskId, prompt: `Turn ${turn} prompt` },
    }) as { success: boolean; submitted: boolean; task_id: string };
    expect(submitResult.success).toBeTruthy();
    expect(submitResult.submitted).toBeTruthy();
    expect(submitResult.task_id).toBe(taskId);

    const observation = await observeUntil(page, taskId, 'completed');
    expect(observation.response).toContain(`Turn ${turn} response for: Turn ${turn} prompt`);
  }
});

test('browser companion submits and observes five sequential Gemini turns', async ({ page }) => {
  await page.addInitScript(installRuntimeStub);
  await page.route('https://gemini.google.com/**', async (route) => {
    await route.fulfill({ status: 200, contentType: 'text/html', body: GEMINI_MULTI_TURN_BODY });
  });
  await page.goto('https://gemini.google.com/app');
  await page.addScriptTag({ path: CONTENT_SCRIPT });

  for (let turn = 1; turn <= 5; turn += 1) {
    const taskId = `gemini-turn-${turn}`;
    const submitResult = await send(page, {
      type: 'marcellus-submit',
      task: { provider: 'gemini', task_id: taskId, prompt: `Turn ${turn} prompt` },
    }) as { success: boolean; submitted: boolean; task_id: string };
    expect(submitResult.success).toBeTruthy();
    expect(submitResult.submitted).toBeTruthy();
    expect(submitResult.task_id).toBe(taskId);

    const observation = await observeUntil(page, taskId, 'completed');
    expect(observation.response).toContain(`Turn ${turn} response for: Turn ${turn} prompt`);
  }
});

test('duplicate marcellus-submit calls for the same task_id click send only once', async ({ page }) => {
  await page.addInitScript(installRuntimeStub);
  await page.route('https://chatgpt.com/**', async (route) => {
    await route.fulfill({ status: 200, contentType: 'text/html', body: CHATGPT_MULTI_TURN_BODY });
  });
  await page.goto('https://chatgpt.com/');
  await page.addScriptTag({ path: CONTENT_SCRIPT });

  const taskId = 'chatgpt-duplicate-task';
  const task = { provider: 'chatgpt', task_id: taskId, prompt: 'Duplicate submission prompt' };

  const first = await send(page, { type: 'marcellus-submit', task }) as { success: boolean; submitted: boolean };
  expect(first.success).toBeTruthy();
  expect(first.submitted).toBeTruthy();

  const second = await send(page, { type: 'marcellus-submit', task }) as { success: boolean; submitted: boolean; task_id: string };
  expect(second.success).toBeTruthy();
  expect(second.submitted).toBeTruthy();
  expect(second.task_id).toBe(taskId);

  const clicks = await page.evaluate(() => (window as unknown as { sendClicks: number }).sendClicks);
  expect(clicks).toBe(1);

  const observation = await observeUntil(page, taskId, 'completed');
  expect(observation.response).toContain('Duplicate submission prompt');
});

test('correlates identical consecutive responses through virtualized node replacement and reordering', async ({ page }) => {
  await page.addInitScript(installRuntimeStub);
  await page.route('https://chatgpt.com/**', (route) => route.fulfill({
    status: 200,
    contentType: 'text/html',
    body: `<!doctype html><html><body>
      <div data-message-author-role="assistant" data-message-id="prior">Identical safe response.</div>
      <div id="prompt-textarea" contenteditable="true" style="width:500px;height:120px"></div>
      <button data-testid="send-button" aria-label="Send prompt" disabled>Send</button>
      <script>
        window.sendClicks = 0;
        const editor = document.querySelector('#prompt-textarea');
        const send = document.querySelector('[data-testid="send-button"]');
        editor.addEventListener('input', () => { send.disabled = !editor.innerText.trim(); });
        send.addEventListener('click', () => {
          window.sendClicks += 1;
          editor.textContent = '';
          send.disabled = true;
          document.querySelectorAll('[data-message-author-role="assistant"]').forEach((node) => node.remove());
          const answer = document.createElement('div');
          answer.dataset.messageAuthorRole = 'assistant';
          answer.dataset.messageId = 'turn-' + window.sendClicks;
          answer.textContent = 'Identical safe response.';
          document.body.prepend(answer);
          const replacement = answer.cloneNode(true);
          answer.replaceWith(replacement);
        });
      </script>
    </body></html>`,
  }));
  await page.goto('https://chatgpt.com/');
  await page.addScriptTag({ path: CONTENT_SCRIPT });

  for (let turn = 1; turn <= 2; turn += 1) {
    const taskId = `identical-${turn}`;
    const submitted = await send(page, {
      type: 'marcellus-submit',
      task: { provider: 'chatgpt', task_id: taskId, prompt: `prompt-${turn}` },
    }) as { success: boolean };
    expect(submitted.success).toBeTruthy();
    const observation = await observeUntil(page, taskId, 'completed');
    expect(observation.response).toBe('Identical safe response.');
  }
  expect(await page.evaluate(() => (window as unknown as { sendClicks: number }).sendClicks)).toBe(2);
});

test('tracks one assistant identity from streaming through a replaced completion node', async ({ page }) => {
  await page.addInitScript(installRuntimeStub);
  await page.route('https://gemini.google.com/**', (route) => route.fulfill({
    status: 200,
    contentType: 'text/html',
    body: `<!doctype html><html><body>
      <rich-textarea><div contenteditable="true" style="width:500px;height:120px"></div></rich-textarea>
      <button id="send" aria-label="Send message" disabled>Send</button>
      <script>
        const editor = document.querySelector('[contenteditable="true"]');
        const send = document.querySelector('#send');
        document.execCommand = (command, _ui, value) => {
          if (command === 'delete') editor.textContent = '';
          if (command === 'insertText') editor.textContent += String(value);
          editor.dispatchEvent(new InputEvent('input', { bubbles: true }));
          return true;
        };
        editor.addEventListener('input', () => { send.disabled = !editor.innerText.trim(); });
        send.addEventListener('click', () => {
          editor.textContent = '';
          send.disabled = true;
          const stop = document.createElement('button');
          stop.setAttribute('aria-label', 'Stop response');
          stop.textContent = 'Stop';
          document.body.appendChild(stop);
          const response = document.createElement('model-response');
          response.dataset.responseId = 'gemini-turn-stable';
          response.innerHTML = '<div class="markdown">Streaming partial response text.</div>';
          document.body.appendChild(response);
          setTimeout(() => {
            const replacement = response.cloneNode(true);
            replacement.querySelector('.markdown').textContent = 'Completed response after node replacement.';
            response.replaceWith(replacement);
            stop.remove();
          }, 150);
        });
      </script>
    </body></html>`,
  }));
  await page.goto('https://gemini.google.com/app');
  await page.addScriptTag({ path: CONTENT_SCRIPT });
  const result = await send(page, {
    type: 'marcellus-submit',
    task: { provider: 'gemini', task_id: 'stream-replacement', prompt: 'stream safely' },
  }) as { success: boolean };
  expect(result.success).toBeTruthy();
  expect((await send(page, { type: 'marcellus-observe', task_id: 'stream-replacement' }) as { state: string }).state)
    .toBe('streaming');
  const completed = await observeUntil(page, 'stream-replacement', 'completed');
  expect(completed.response).toBe('Completed response after node replacement.');
});

test('marcellus-observe recovers after a reload-compatible content script reinjection', async ({ page }) => {
  await page.addInitScript(installRuntimeStub);
  let reloadBody = CHATGPT_MULTI_TURN_BODY;
  await page.route('https://chatgpt.com/**', async (route) => {
    await route.fulfill({ status: 200, contentType: 'text/html', body: reloadBody });
  });
  await page.goto('https://chatgpt.com/');
  await page.addScriptTag({ path: CONTENT_SCRIPT });

  const staleTaskId = 'chatgpt-before-reload';
  const submitResult = await send(page, {
    type: 'marcellus-submit',
    task: { provider: 'chatgpt', task_id: staleTaskId, prompt: 'Before reload prompt' },
  }) as { success: boolean };
  expect(submitResult.success).toBeTruthy();
  reloadBody = await page.content();

  // Simulate a tab/content-script reload: a fresh document means the content script's
  // module-scope state, including taskRecords, is rebuilt from scratch. The runtime stub
  // was registered via addInitScript, so it re-applies automatically on reload.
  await page.reload();
  await page.addScriptTag({ path: CONTENT_SCRIPT });

  const duplicateSubmit = await send(page, {
    type: 'marcellus-submit',
    task: { provider: 'chatgpt', task_id: staleTaskId, prompt: 'Before reload prompt' },
  }) as { success: boolean };
  expect(duplicateSubmit.success).toBeTruthy();
  expect(await page.evaluate(() => (window as unknown as { sendClicks: number }).sendClicks)).toBe(0);

  const observation = await observeUntil(page, staleTaskId, 'completed');
  expect(observation.response).toContain('Before reload prompt');
});

test('marcellus-cancel marks a task cancelled without persisting its response', async ({ page }) => {
  await page.addInitScript(installRuntimeStub);
  await page.route('https://chatgpt.com/**', async (route) => {
    await route.fulfill({ status: 200, contentType: 'text/html', body: CHATGPT_MULTI_TURN_BODY });
  });
  await page.goto('https://chatgpt.com/');
  await page.addScriptTag({ path: CONTENT_SCRIPT });

  const taskId = 'chatgpt-cancel-task';
  const submitResult = await send(page, {
    type: 'marcellus-submit',
    task: { provider: 'chatgpt', task_id: taskId, prompt: 'Cancel me before completion' },
  }) as { success: boolean };
  expect(submitResult.success).toBeTruthy();

  const cancelResult = await send(page, { type: 'marcellus-cancel', task_id: taskId }) as { success: boolean; task_id: string };
  expect(cancelResult.success).toBeTruthy();
  expect(cancelResult.task_id).toBe(taskId);

  const observation = await send(page, { type: 'marcellus-observe', task_id: taskId }) as { state: string; response?: string };
  expect(observation.state).toBe('cancelled');
  expect(observation.response).toBeUndefined();
});

test('background journal storage never contains prompt, response, or token fields', async ({ page }) => {
  await page.addInitScript(() => {
    const store: Record<string, unknown> = {};
    (window as unknown as { __testStore: Record<string, unknown> }).__testStore = store;
    const chromeStub = {
      storage: {
        local: {
          get(keys: unknown, callback: (value: Record<string, unknown>) => void) {
            const list = Array.isArray(keys) ? keys : [keys];
            const result: Record<string, unknown> = {};
            for (const key of list as string[]) result[key] = store[key];
            callback(result);
          },
          set(values: Record<string, unknown>, callback?: () => void) {
            Object.assign(store, values);
            callback?.();
          },
          remove(_key: string, callback?: () => void) {
            callback?.();
          },
        },
      },
      tabs: {
        query(_query: unknown, callback: (tabs: unknown[]) => void) { callback([]); },
        get(_id: number, callback: (tab: unknown) => void) { callback(undefined); },
        create(options: { url: string }, callback: (tab: unknown) => void) {
          callback({ id: 1, url: options.url, status: 'complete' });
        },
        update(_id: number, _update: unknown, callback?: () => void) { callback?.(); },
        sendMessage(_id: number, _message: unknown, callback: (response: unknown) => void) { callback(undefined); },
        onRemoved: { addListener() {} },
        onUpdated: { addListener() {} },
      },
      alarms: { create() {}, onAlarm: { addListener() {} } },
      runtime: { onMessage: { addListener() {} }, onInstalled: { addListener() {} }, lastError: null },
    };
    Object.defineProperty(window, 'chrome', { value: chromeStub, configurable: true });
  });

  await page.goto('about:blank');
  await page.addScriptTag({ path: BACKGROUND_SCRIPT });

  await page.evaluate(async () => {
    const upsert = (window as unknown as { upsertJournalEntry: (entry: Record<string, unknown>) => Promise<unknown> })
      .upsertJournalEntry;
    await upsert({
      task_id: 'journal-secret-task',
      provider: 'chatgpt',
      session_id: 'session-1',
      state: 'submitted',
      leased_at: Date.now(),
      lease_expires_at: Date.now() + 20000,
      attempts: 1,
      tab_id: 1,
      url: 'https://chatgpt.com/',
      progress_at: Date.now(),
      detail: '',
      error_code: 'submit_failed',
      prompt: 'TOP SECRET PROMPT',
      response: 'TOP SECRET RESPONSE',
      token: 'super-secret-token',
    });
  });

  const journal = await page.evaluate(() => (
    (window as unknown as { __testStore: Record<string, unknown> }).__testStore.marcellusTaskJournal
  )) as Record<string, Record<string, unknown>>;

  expect(journal['journal-secret-task']).toBeTruthy();
  const entry = journal['journal-secret-task'];
  expect(entry.prompt).toBeUndefined();
  expect(entry.response).toBeUndefined();
  expect(entry.token).toBeUndefined();
  expect(entry.detail).toBeUndefined();
  expect(entry.error_code).toBe('submit_failed');
  expect(entry.state).toBe('submitted');
  expect(entry.task_id).toBe('journal-secret-task');

  const serialized = JSON.stringify(journal);
  expect(serialized).not.toContain('TOP SECRET');
  expect(serialized).not.toContain('super-secret-token');
});

test('persists delayed SPA conversation URLs and restores the same sanitized conversation', async ({ page }) => {
  await page.addInitScript(() => {
    const store: Record<string, unknown> = {
      marcellusSessionTabs: {
        'chatgpt:session-delayed': { tab_id: 3, url: 'https://chatgpt.com/' },
      },
    };
    const listeners: Record<string, ((...args: unknown[]) => void) | undefined> = {};
    const createdUrls: string[] = [];
    Object.defineProperty(window, '__browserTestState', {
      value: { store, listeners, createdUrls }, configurable: true,
    });
    const chromeStub = {
      storage: {
        local: {
          get(keys: unknown, callback: (value: Record<string, unknown>) => void) {
            const list = Array.isArray(keys) ? keys : [keys];
            callback(Object.fromEntries((list as string[]).map((key) => [key, store[key]])));
          },
          set(values: Record<string, unknown>, callback?: () => void) {
            Object.assign(store, values);
            callback?.();
          },
          remove(_key: string, callback?: () => void) { callback?.(); },
        },
      },
      tabs: {
        query(_query: unknown, callback: (tabs: unknown[]) => void) { callback([]); },
        get(id: number, callback: (tab: unknown) => void) {
          callback(
            id === 3
              ? { id, url: 'https://chatgpt.com/c/thread-42', status: 'complete' }
              : id === 7
                ? { id, url: 'https://chatgpt.com/c/thread-42', status: 'complete' }
                : undefined,
          );
        },
        create(options: { url: string }, callback: (tab: unknown) => void) {
          createdUrls.push(options.url);
          callback({ id: 7, url: options.url, status: 'complete' });
        },
        update(_id: number, _update: unknown, callback?: () => void) { callback?.(); },
        sendMessage(_id: number, message: { type?: string }, callback: (response: unknown) => void) {
          callback(message.type === 'marcellus-status' ? { ready: true } : undefined);
        },
        onRemoved: { addListener(listener: (...args: unknown[]) => void) { listeners.removed = listener; } },
        onUpdated: { addListener(listener: (...args: unknown[]) => void) { listeners.updated = listener; } },
      },
      alarms: { create() {}, onAlarm: { addListener() {} } },
      runtime: { onMessage: { addListener() {} }, onInstalled: { addListener() {} }, lastError: null },
    };
    Object.defineProperty(window, 'chrome', { value: chromeStub, configurable: true });
  });

  await page.goto('about:blank');
  await page.addScriptTag({ path: BACKGROUND_SCRIPT });
  await page.evaluate(async () => {
    const state = (window as unknown as { __browserTestState: {
      listeners: Record<string, (...args: unknown[]) => void>;
    } }).__browserTestState;
    state.listeners.updated(3, {
      url: 'https://chatgpt.com/c/thread-42?temporary=secret#fragment',
    }, { id: 3, url: 'https://chatgpt.com/c/thread-42' });
    await new Promise((resolve) => setTimeout(resolve, 20));
    state.listeners.removed(3);
    await new Promise((resolve) => setTimeout(resolve, 20));
    const sessionTab = (window as unknown as {
      sessionTab: (task: Record<string, unknown>) => Promise<unknown>;
    }).sessionTab;
    await sessionTab({ provider: 'chatgpt', session_id: 'session-delayed' });
  });

  const state = await page.evaluate(() => (
    window as unknown as { __browserTestState: {
      store: Record<string, unknown>;
      createdUrls: string[];
    } }
  ).__browserTestState) as {
    store: { marcellusSessionTabs: Record<string, { tab_id: number | null; url: string }> };
    createdUrls: string[];
  };
  const mapping = state.store.marcellusSessionTabs['chatgpt:session-delayed'];
  expect(state.createdUrls).toEqual(['https://chatgpt.com/c/thread-42']);
  expect(mapping).toEqual({ tab_id: 7, url: 'https://chatgpt.com/c/thread-42' });
  expect(JSON.stringify(state.store)).not.toContain('temporary=secret');
  expect(JSON.stringify(state.store)).not.toContain('#fragment');
});

test('browser companion submits the complete ChatGPT prompt', async ({ page }) => {
  await page.addInitScript(() => {
    const runtime = {
      listener: null as null | ((message: unknown, sender: unknown, callback: (value: unknown) => void) => boolean),
      onMessage: {
        addListener(listener: typeof runtime.listener) {
          runtime.listener = listener;
        },
      },
      sendMessage() {},
    };
    Object.defineProperty(window, 'chrome', { value: { runtime }, configurable: true });
    Object.defineProperty(window, '__enksteinRuntime', { value: runtime, configurable: true });
  });
  await page.route('https://chatgpt.com/**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: `<!doctype html><html><body>
        <div id="prompt-textarea" contenteditable="true" style="width:500px;height:120px"></div>
        <button data-testid="send-button" aria-label="Send prompt" disabled>Send</button>
        <script>
          const editor = document.querySelector('#prompt-textarea');
          const send = document.querySelector('[data-testid="send-button"]');
          editor.addEventListener('input', () => { send.disabled = !editor.innerText.trim(); });
          send.addEventListener('click', () => {
            window.submittedPrompt = editor.innerText;
            editor.textContent = '';
            send.disabled = true;
            const answer = document.createElement('div');
            answer.dataset.messageAuthorRole = 'assistant';
            answer.textContent = 'The complete PowerShell script was received and reviewed successfully.';
            document.body.appendChild(answer);
          });
        </script>
      </body></html>`,
    });
  });

  await page.goto('https://chatgpt.com/');
  await page.addScriptTag({ path: path.resolve(process.cwd(), '../browser-extension/content.js') });
  const prompt = `Review this PowerShell script:\n${'Write-Output "complete-line"\n'.repeat(1400)}`;
  const result = await page.evaluate(async (message) => {
    const runtime = (window as unknown as { __enksteinRuntime: { listener: Function } }).__enksteinRuntime;
    return new Promise((resolve) => {
      runtime.listener({ type: 'marcellus-execute', task: { provider: 'chatgpt', prompt: message } }, {}, resolve);
    });
  }, prompt) as { success: boolean; response: string };

  expect(result.success).toBeTruthy();
  expect(result.response).toContain('complete PowerShell script');
  const submitted = await page.evaluate(() => (window as unknown as { submittedPrompt: string }).submittedPrompt);
  expect(submitted.trimEnd()).toBe(prompt.trimEnd());
  expect(submitted.split('complete-line').length).toBe(prompt.split('complete-line').length);
  await expect(page.locator('#prompt-textarea')).toHaveText('');
});

test('browser companion supports a controlled editor that accepts paste transactions', async ({ page }) => {
  await page.addInitScript(() => {
    const runtime = {
      listener: null as null | ((message: unknown, sender: unknown, callback: (value: unknown) => void) => boolean),
      onMessage: { addListener(listener: typeof runtime.listener) { runtime.listener = listener; } },
      sendMessage() {},
    };
    Object.defineProperty(window, 'chrome', { value: { runtime }, configurable: true });
    Object.defineProperty(window, '__enksteinRuntime', { value: runtime, configurable: true });
  });
  await page.route('https://chatgpt.com/**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: `<!doctype html><html><body>
        <div id="prompt-textarea" contenteditable="true" style="width:500px;height:120px"></div>
        <button data-testid="send-button" aria-label="Send prompt" disabled>Send</button>
        <script>
          const editor = document.querySelector('#prompt-textarea');
          const send = document.querySelector('[data-testid="send-button"]');
          document.execCommand = () => false;
          let pasteAccepted = false;
          editor.addEventListener('paste', (event) => {
            event.preventDefault();
            pasteAccepted = true;
            editor.textContent = event.clipboardData.getData('text/plain');
            editor.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertFromPaste' }));
          });
          editor.addEventListener('input', () => {
            if (!pasteAccepted) editor.textContent = '';
            send.disabled = !editor.innerText.trim();
          });
          send.addEventListener('click', () => {
            window.submittedPrompt = editor.innerText;
            editor.textContent = '';
            send.disabled = true;
            const answer = document.createElement('div');
            answer.dataset.messageAuthorRole = 'assistant';
            answer.textContent = 'Controlled editor response completed.';
            document.body.appendChild(answer);
          });
        </script>
      </body></html>`,
    });
  });

  await page.goto('https://chatgpt.com/');
  await page.addScriptTag({ path: path.resolve(process.cwd(), '../browser-extension/content.js') });
  const result = await page.evaluate(async () => {
    const runtime = (window as unknown as { __enksteinRuntime: { listener: Function } }).__enksteinRuntime;
    return new Promise((resolve) => runtime.listener(
      { type: 'marcellus-execute', task: { provider: 'chatgpt', prompt: 'Review the controlled editor.' } },
      {},
      resolve,
    ));
  }) as { success: boolean; response: string };

  expect(result.success).toBeTruthy();
  expect(result.response).toContain('Controlled editor response');
  expect(await page.evaluate(() => (window as unknown as { submittedPrompt: string }).submittedPrompt))
    .toBe('Review the controlled editor.');
});

test('browser companion preserves multiline prompts in the Gemini editor', async ({ page }) => {
  await page.addInitScript(() => {
    const runtime = {
      listener: null as null | ((message: unknown, sender: unknown, callback: (value: unknown) => void) => boolean),
      onMessage: { addListener(listener: typeof runtime.listener) { runtime.listener = listener; } },
      sendMessage() {},
    };
    Object.defineProperty(window, 'chrome', { value: { runtime }, configurable: true });
    Object.defineProperty(window, '__enksteinRuntime', { value: runtime, configurable: true });
  });
  await page.route('https://gemini.google.com/**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: `<!doctype html><html><body>
        <rich-textarea><div contenteditable="true" style="width:500px;height:120px;white-space:pre-wrap"></div></rich-textarea>
        <button aria-label="Send message" disabled>Send</button>
        <script>
          const editor = document.querySelector('[contenteditable="true"]');
          const send = document.querySelector('button');
          document.execCommand = (command, _ui, value) => {
            if (command === 'delete') editor.textContent = '';
            if (command === 'insertText') editor.textContent += String(value).split('\\n')[0];
            if (command === 'insertParagraph' || command === 'insertLineBreak') editor.textContent += '\\n';
            editor.dispatchEvent(new InputEvent('input', { bubbles: true }));
            return true;
          };
          editor.addEventListener('input', () => { send.disabled = !editor.innerText.trim(); });
          send.addEventListener('click', () => {
            window.submittedPrompt = editor.innerText;
            editor.textContent = '';
            send.disabled = true;
            const response = document.createElement('model-response');
            response.innerHTML = '<div class="markdown">Gemini multiline response completed.</div>';
            document.body.appendChild(response);
          });
        </script>
      </body></html>`,
    });
  });

  await page.goto('https://gemini.google.com/app');
  await page.addScriptTag({ path: path.resolve(process.cwd(), '../browser-extension/content.js') });
  const prompt = 'Governance preamble.\n\nQUESTION:\nReview this multiline request.';
  const result = await page.evaluate(async (message) => {
    const runtime = (window as unknown as { __enksteinRuntime: { listener: Function } }).__enksteinRuntime;
    return new Promise((resolve) => runtime.listener(
      { type: 'marcellus-execute', task: { provider: 'gemini', prompt: message } },
      {},
      resolve,
    ));
  }, prompt) as { success: boolean; response: string };

  expect(result.success).toBeTruthy();
  expect(result.response).toContain('Gemini multiline response');
  expect(await page.evaluate(() => (window as unknown as { submittedPrompt: string }).submittedPrompt))
    .toBe(prompt);
});

test('browser companion recovers from Gemini silently truncating a large single insertText call', async ({ page }) => {
  await page.addInitScript(installRuntimeStub);
  await page.route('https://gemini.google.com/**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: `<!doctype html><html><body>
        <rich-textarea><div contenteditable="true" style="width:500px;height:120px;white-space:pre-wrap"></div></rich-textarea>
        <button aria-label="Send message" disabled>Send</button>
        <script>
          // Reproduces the real observed bug: a single execCommand('insertText')
          // call with a long value silently truncates to a cap, but still
          // returns true, so callers cannot detect the loss from the return
          // value alone -- only by comparing the editor's resulting content.
          // The stub also models a framework-controlled editor (React/Angular
          // style): direct DOM writes that did not go through execCommand are
          // reverted back to the editor's last known-good internal value on
          // the next input tick, so a blind "element.textContent = text"
          // recovery cannot succeed -- only genuinely verified, small,
          // execCommand-driven inserts can.
          const editor = document.querySelector('[contenteditable="true"]');
          const send = document.querySelector('button');
          const TRUNCATE_CAP = 40;
          let internalValue = '';
          document.execCommand = (command, _ui, value) => {
            if (command === 'delete') { internalValue = ''; editor.textContent = ''; return true; }
            if (command === 'insertText') {
              // Any single call longer than the cap is silently truncated,
              // matching the real observed Gemini behavior; calls at or
              // under the cap (like our small verified chunks) apply in full.
              const applied = String(value).slice(0, TRUNCATE_CAP);
              internalValue += applied;
              editor.textContent += applied;
              editor.dispatchEvent(new InputEvent('input', { bubbles: true }));
              return true;
            }
            if (command === 'insertParagraph' || command === 'insertLineBreak') {
              internalValue += '\\n';
              editor.textContent += '\\n';
              editor.dispatchEvent(new InputEvent('input', { bubbles: true }));
              return true;
            }
            return false;
          };
          editor.addEventListener('input', (event) => {
            if (event.inputType === 'insertFromPaste') {
              // Simulate a controlled editor rejecting an unsanctioned direct
              // DOM write and reverting to its authoritative internal model.
              editor.textContent = internalValue;
            }
          });
          editor.addEventListener('input', () => { send.disabled = !editor.innerText.trim(); });
          send.addEventListener('click', () => {
            window.submittedPrompt = editor.innerText;
            editor.textContent = '';
            internalValue = '';
            send.disabled = true;
            const response = document.createElement('model-response');
            response.innerHTML = '<div class="markdown">Gemini truncation-recovery response completed.</div>';
            document.body.appendChild(response);
          });
        </script>
      </body></html>`,
    });
  });

  await page.goto('https://gemini.google.com/app');
  await page.addScriptTag({ path: CONTENT_SCRIPT });
  const prompt = 'This is a long governed prompt that exceeds the truncation cap of the simulated Gemini editor and must survive intact.';
  const result = await page.evaluate(async (message) => {
    const runtime = (window as unknown as { __enksteinRuntime: { listener: Function } }).__enksteinRuntime;
    return new Promise((resolve) => runtime.listener(
      { type: 'marcellus-execute', task: { provider: 'gemini', prompt: message } },
      {},
      resolve,
    ));
  }, prompt) as { success: boolean; response: string };

  expect(result.success).toBeTruthy();
  expect(result.response).toContain('Gemini truncation-recovery response');
  expect(await page.evaluate(() => (window as unknown as { submittedPrompt: string }).submittedPrompt))
    .toBe(prompt);
});
