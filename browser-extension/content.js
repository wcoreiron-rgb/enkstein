function provider() {
  if (location.hostname === 'chatgpt.com') return 'chatgpt';
  if (location.hostname === 'claude.ai') return 'claude';
  return 'gemini';
}

const INPUT_SELECTORS = {
  chatgpt: ['#prompt-textarea', 'textarea[placeholder]', 'div[contenteditable="true"]'],
  claude: ['div[contenteditable="true"].ProseMirror', 'div[contenteditable="true"]', 'textarea'],
  gemini: ['rich-textarea div[contenteditable="true"]', 'div[contenteditable="true"]', 'textarea'],
};

const RESPONSE_SELECTORS = {
  chatgpt: ['[data-message-author-role="assistant"]'],
  claude: ['[data-testid="assistant-message"]', '.font-claude-response', '[data-is-streaming]'],
  gemini: ['model-response .markdown', 'model-response', '.model-response-text'],
};

function visible(element) {
  const style = getComputedStyle(element);
  const rect = element.getBoundingClientRect();
  return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
}

function findInput(kind) {
  for (const selector of INPUT_SELECTORS[kind]) {
    const candidates = [...document.querySelectorAll(selector)].filter(visible);
    if (candidates.length) return candidates[candidates.length - 1];
  }
  return null;
}

function setInput(element, text) {
  element.focus();
  if (element instanceof HTMLTextAreaElement || element instanceof HTMLInputElement) {
    const prototype = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
    if (setter) setter.call(element, text);
    else element.value = text;
  } else {
    element.textContent = text;
  }
  element.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: text }));
  element.dispatchEvent(new Event('change', { bubbles: true }));
}

function responseTexts(kind) {
  const values = [];
  for (const selector of RESPONSE_SELECTORS[kind]) {
    for (const element of document.querySelectorAll(selector)) {
      if (!visible(element)) continue;
      const text = (element.innerText || element.textContent || '').trim();
      if (text.length >= 2) values.push(text);
    }
  }
  return [...new Set(values)];
}

function submit(input) {
  const buttons = [...document.querySelectorAll('button')].filter((button) => {
    if (!visible(button) || button.disabled) return false;
    const label = `${button.getAttribute('aria-label') || ''} ${button.getAttribute('data-testid') || ''}`.toLowerCase();
    return label.includes('send') || label.includes('submit');
  });
  if (buttons.length) {
    buttons[buttons.length - 1].click();
    return;
  }
  input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', bubbles: true }));
  input.dispatchEvent(new KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', bubbles: true }));
}

async function waitForResponse(kind, baseline, timeoutMs = 180000) {
  const deadline = Date.now() + timeoutMs;
  let previous = '';
  let stable = 0;
  await new Promise((resolve) => setTimeout(resolve, 2000));
  while (Date.now() < deadline) {
    const candidates = responseTexts(kind).filter((text) => !baseline.has(text));
    const candidate = candidates[candidates.length - 1] || '';
    if (candidate.length >= 12) {
      if (candidate === previous) stable += 1;
      else { previous = candidate; stable = 0; }
      if (stable >= 4) return candidate;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error('The visible provider response did not complete before the Marcellus timeout.');
}

async function execute(task) {
  const kind = provider();
  if (kind !== task.provider) throw new Error('The active tab does not match the requested provider.');
  const input = findInput(kind);
  if (!input) throw new Error('No compatible signed-in message field is visible on this provider page.');
  const baseline = new Set(responseTexts(kind));
  setInput(input, task.prompt);
  submit(input);
  return waitForResponse(kind, baseline);
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'marcellus-status') {
    sendResponse({ ready: Boolean(findInput(provider())) });
    return false;
  }
  if (message?.type !== 'marcellus-execute') return false;
  execute(message.task).then((response) => sendResponse({ success: true, response })).catch((error) => {
    sendResponse({ success: false, detail: error instanceof Error ? error.message : 'Browser invocation failed.' });
  });
  return true;
});

setInterval(() => chrome.runtime.sendMessage({ type: 'marcellus-heartbeat' }), 2000);
chrome.runtime.sendMessage({ type: 'marcellus-heartbeat' });
