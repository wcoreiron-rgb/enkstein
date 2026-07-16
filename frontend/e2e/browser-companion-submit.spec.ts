import path from 'node:path';
import { expect, test } from '@playwright/test';

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
