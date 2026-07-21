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

const STREAMING_SELECTORS = {
  chatgpt: ['button[data-testid="stop-button"]', 'button[aria-label*="Stop generating" i]', 'button[aria-label*="Stop streaming" i]'],
  claude: ['[data-is-streaming="true"]', 'button[aria-label*="Stop response" i]'],
  gemini: ['button[aria-label*="Stop response" i]', 'button[aria-label*="Stop generating" i]'],
};

// Keyed by task_id. Holds only ephemeral submission/observation state — never
// persists the prompt or response text. Element correlation uses provider IDs
// when available, otherwise an extension-owned opaque marker placed on the
// assistant element. It never relies on response counts or response content.
const taskRecords = new Map();
const TASK_SESSION_PREFIX = 'enkstein-browser-task:';
const MESSAGE_MARKER = 'data-enkstein-message-fingerprint';
const SAFE_MESSAGE_ID_ATTRIBUTES = ['data-message-id', 'data-turn-id', 'data-response-id'];
const elementFirstSeen = new WeakMap();

const messageObserver = new MutationObserver((mutations) => {
  const seenAt = Date.now();
  for (const mutation of mutations) {
    for (const node of mutation.addedNodes) {
      if (!(node instanceof Element)) continue;
      elementFirstSeen.set(node, seenAt);
      for (const child of node.querySelectorAll('*')) elementFirstSeen.set(child, seenAt);
    }
  }
});
messageObserver.observe(document.documentElement, { childList: true, subtree: true });

function sessionTaskKey(taskId) {
  return `${TASK_SESSION_PREFIX}${taskId}`;
}

function persistTaskMetadata(taskId, record) {
  try {
    sessionStorage.setItem(sessionTaskKey(taskId), JSON.stringify({
      provider: record.provider,
      status: record.status,
      submittedAt: record.submittedAt,
      lastAssistantId: record.lastAssistantId || null,
      lastAssistantFingerprint: record.lastAssistantFingerprint || null,
      responseIdentity: record.responseIdentity || null,
    }));
  } catch {}
}

function recoverTaskMetadata(taskId) {
  try {
    const raw = sessionStorage.getItem(sessionTaskKey(taskId));
    if (!raw) return null;
    const saved = JSON.parse(raw);
    if (!saved || saved.provider !== provider() || !Number.isFinite(saved.submittedAt)) return null;
    const record = {
      provider: saved.provider,
      status: saved.status === 'cancelled' ? 'cancelled' : 'submitted',
      submittedAt: saved.submittedAt,
      lastAssistantId: typeof saved.lastAssistantId === 'string' ? saved.lastAssistantId : null,
      lastAssistantFingerprint: typeof saved.lastAssistantFingerprint === 'string' ? saved.lastAssistantFingerprint : null,
      responseIdentity: typeof saved.responseIdentity === 'string' ? saved.responseIdentity : null,
      recovered: true,
      sample: { previous: '', identity: null, stable: 0 },
    };
    taskRecords.set(taskId, record);
    return record;
  } catch {
    return null;
  }
}

const SEND_SELECTORS = {
  chatgpt: [
    'button[data-testid="send-button"]',
    'button[aria-label*="Send prompt" i]',
    'button[aria-label*="Send message" i]',
  ],
  claude: [
    'button[aria-label*="Send Message" i]',
    'button[data-testid*="send" i]',
  ],
  gemini: [
    'button[aria-label*="Send message" i]',
    'button[aria-label*="Send" i]',
    'button.send-button',
  ],
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

function inputText(element) {
  if (element instanceof HTMLTextAreaElement || element instanceof HTMLInputElement) {
    return element.value;
  }
  return element.innerText || element.textContent || '';
}

function normalizedInputText(text) {
  return String(text || '')
    .normalize('NFKC')
    .replace(/\r\n?/g, '\n')
    .replace(/\u00a0/g, ' ')
    .replace(/[\u200b-\u200d\ufeff]/g, '')
    .replace(/[^\S\n]+/g, ' ')
    .replace(/\n+/g, '\n')
    .trim();
}

function inputMatches(element, text) {
  return normalizedInputText(inputText(element)) === normalizedInputText(text);
}

async function waitForInput(element, text, timeoutMs = 2500) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (inputMatches(element, text)) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return inputMatches(element, text);
}

function selectInputContents(element) {
  const selection = window.getSelection();
  const range = document.createRange();
  range.selectNodeContents(element);
  selection?.removeAllRanges();
  selection?.addRange(range);
}

function dispatchEditorInput(element, text, inputType = 'insertText') {
  element.dispatchEvent(new InputEvent('input', {
    bubbles: true,
    composed: true,
    inputType,
    data: text,
  }));
}

function dispatchEditorPaste(element, text) {
  try {
    const clipboardData = new DataTransfer();
    clipboardData.setData('text/plain', text);
    element.dispatchEvent(new ClipboardEvent('paste', {
      bubbles: true,
      cancelable: true,
      composed: true,
      clipboardData,
    }));
    return true;
  } catch {
    return false;
  }
}

// execCommand('insertText') can silently truncate a large single call while
// still returning true (observed on Gemini's rich-textarea editor: a ~560
// char prompt landed as ~134 chars with no error). This inserts in small,
// individually-verified chunks, re-reading the editor's real content after
// every chunk so a partial/truncated insertion is caught at the exact point
// it happens rather than only once at the very end of one large call.
const VERIFIED_INSERT_CHUNK_SIZE = 120;

async function insertOneVerifiedPass(element, text, chunkSize) {
  selectInputContents(element);
  document.execCommand('delete', false);
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    for (let offset = 0; offset < line.length; offset += chunkSize) {
      const segment = line.slice(offset, offset + chunkSize);
      const expectedSoFar = lines.slice(0, lineIndex).join('\n')
        + (lineIndex > 0 ? '\n' : '')
        + line.slice(0, offset + segment.length);
      document.execCommand('insertText', false, segment);
      // execCommand's return value can report success even when a call
      // silently truncates (the exact bug observed with Gemini's editor:
      // a ~560 char prompt landed as ~134 chars with no error signalled).
      // Re-read the editor after every chunk and compare against the exact
      // text expected at this point so truncation is caught immediately
      // rather than only once at the very end of the whole insertion.
      if (normalizedInputText(inputText(element)) !== normalizedInputText(expectedSoFar)) {
        return false;
      }
    }
    if (lineIndex < lines.length - 1) {
      document.execCommand('insertParagraph', false) || document.execCommand('insertLineBreak', false);
      const expectedSoFar = lines.slice(0, lineIndex + 1).join('\n') + '\n';
      if (normalizedInputText(inputText(element)) !== normalizedInputText(expectedSoFar)) {
        return false;
      }
    }
  }
  return normalizedInputText(inputText(element)) === normalizedInputText(text);
}

async function insertVerifiedChunks(element, text) {
  // Try progressively smaller chunk sizes. Each attempt clears the editor and
  // reinserts from scratch (never resumes mid-attempt), so a partial/failed
  // pass at one chunk size can never leave stale, unverifiable content behind
  // for the next attempt to build on top of.
  for (let chunkSize = VERIFIED_INSERT_CHUNK_SIZE; chunkSize >= 1; chunkSize = chunkSize === 1 ? 0 : Math.max(1, Math.floor(chunkSize / 8))) {
    if (await insertOneVerifiedPass(element, text, chunkSize)) {
      return { complete: true };
    }
  }
  return { complete: false };
}

async function setInput(element, text, kind) {
  element.focus();
  if (element instanceof HTMLTextAreaElement || element instanceof HTMLInputElement) {
    const prototype = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
    if (setter) setter.call(element, text);
    else element.value = text;
    dispatchEditorInput(element, text);
  } else {
    // Provider editors are controlled contenteditables. Use the native editing
    // path first so ProseMirror/React receives a real beforeinput/input cycle.
    selectInputContents(element);
    document.execCommand('delete', false);
    const inserted = document.execCommand('insertText', false, text);
    if (inserted && await waitForInput(element, text)) {
      element.dispatchEvent(new Event('change', { bubbles: true }));
      return;
    }

    // ProseMirror-based provider editors may ignore direct DOM/input changes
    // but accept a paste transaction and update their internal document state.
    if (kind !== 'gemini') {
      selectInputContents(element);
      document.execCommand('delete', false);
      if (dispatchEditorPaste(element, text) && await waitForInput(element, text)) {
        element.dispatchEvent(new Event('change', { bubbles: true }));
        return;
      }
    }

    // Insert in small, individually-verified chunks, shrinking the chunk size
    // on failure. This catches a partial/truncated insertion at the exact
    // point it happens (rather than only once at the very end of one large
    // call) instead of trusting execCommand's return value, which can report
    // success even when a provider editor silently truncates the input.
    const { complete } = await insertVerifiedChunks(element, text);
    if (complete && await waitForInput(element, text)) {
      element.dispatchEvent(new Event('change', { bubbles: true }));
      return;
    } else {
      // Final compatibility path for controlled editors that only synchronize
      // after their DOM has been populated and an input event is dispatched.
      element.textContent = text;
      dispatchEditorInput(element, text, 'insertFromPaste');
    }
  }
  element.dispatchEvent(new Event('change', { bubbles: true }));
  await waitForInput(element, text);
}

function findSendButton(kind) {
  for (const selector of SEND_SELECTORS[kind]) {
    const candidates = [...document.querySelectorAll(selector)].filter((button) => (
      button instanceof HTMLButtonElement && visible(button) && !button.disabled && button.getAttribute('aria-disabled') !== 'true'
    ));
    if (candidates.length) return candidates[candidates.length - 1];
  }
  return [...document.querySelectorAll('button')].filter((button) => {
    if (!(button instanceof HTMLButtonElement) || !visible(button) || button.disabled) return false;
    const label = `${button.getAttribute('aria-label') || ''} ${button.getAttribute('data-testid') || ''}`.toLowerCase();
    return label.includes('send') || label.includes('submit');
  }).pop() || null;
}

async function waitForSendButton(kind, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const button = findSendButton(kind);
    if (button) return button;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('The provider message field did not enable its Send button. Reload the provider tab and try again.');
}

function responseElements(kind) {
  const values = [];
  const seen = new Set();
  for (const selector of RESPONSE_SELECTORS[kind]) {
    for (const element of document.querySelectorAll(selector)) {
      if (!visible(element) || seen.has(element)) continue;
      seen.add(element);
      values.push(element);
    }
  }
  return values;
}

function boundedSafeId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,160}$/.test(value) ? value : null;
}

function providerMessageId(element) {
  for (const candidate of [element, element.closest('[data-message-id],[data-turn-id],[data-response-id]')]) {
    if (!candidate) continue;
    for (const attribute of SAFE_MESSAGE_ID_ATTRIBUTES) {
      const value = boundedSafeId(candidate.getAttribute(attribute));
      if (value) return `${attribute}:${value}`;
    }
    const id = boundedSafeId(candidate.id);
    if (id) return `id:${id}`;
  }
  return null;
}

function elementFingerprint(element) {
  const providerId = providerMessageId(element);
  if (providerId) return `provider:${providerId}`;
  let marker = boundedSafeId(element.getAttribute(MESSAGE_MARKER));
  if (!marker) {
    marker = crypto.randomUUID();
    element.setAttribute(MESSAGE_MARKER, marker);
  }
  return `marker:${marker}`;
}

function assistantDescriptor(element) {
  return {
    element,
    id: providerMessageId(element),
    fingerprint: elementFingerprint(element),
    seenAt: elementFirstSeen.get(element) || 0,
  };
}

function lastAssistantDescriptor(kind) {
  const elements = responseElements(kind);
  return elements.length ? assistantDescriptor(elements[elements.length - 1]) : null;
}

function correlatedAssistant(kind, record) {
  const descriptors = responseElements(kind).map(assistantDescriptor);
  if (!descriptors.length) return null;

  if (record.responseIdentity) {
    const retained = descriptors.find((item) => item.id === record.responseIdentity || item.fingerprint === record.responseIdentity);
    if (retained) return retained;
  }

  const candidates = descriptors.filter((item) => {
    if (record.lastAssistantId && item.id === record.lastAssistantId) return false;
    if (record.lastAssistantFingerprint && item.fingerprint === record.lastAssistantFingerprint) return false;
    // A live MutationObserver timestamp is strong evidence. After a content
    // script restart, the persisted last-assistant identity is the boundary and
    // safely distinguishes the newly submitted turn without response counts.
    return item.seenAt >= record.submittedAt || record.recovered === true;
  });
  return candidates[candidates.length - 1] || null;
}

async function waitForSubmission(input, originalText, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const remaining = inputText(input).trim();
    if (!remaining || remaining !== originalText.trim()) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('The prompt remained in the provider message field and was not submitted. Reload the provider tab and try again.');
}

async function submit(kind, input, text) {
  const button = await waitForSendButton(kind);
  button.click();
  await waitForSubmission(input, text);
}

function isStreaming(kind) {
  const selectors = STREAMING_SELECTORS[kind] || [];
  return selectors.some((selector) => [...document.querySelectorAll(selector)].some(visible));
}

async function handleSubmit(task) {
  const taskId = task?.task_id;
  const taskProvider = task?.provider;
  if (!taskId || typeof taskId !== 'string') {
    return { success: false, detail: 'A task_id is required.' };
  }
  if (!taskProvider) {
    return { success: false, detail: 'A provider is required.' };
  }
  const kind = provider();
  if (kind !== taskProvider) {
    return { success: false, detail: 'The active tab does not match the requested provider.' };
  }

  const existing = taskRecords.get(taskId) || recoverTaskMetadata(taskId);
  if (existing) {
    return { success: true, submitted: true, task_id: taskId };
  }

  try {
    // A provider can expose its composer before React/ProseMirror has attached
    // the controlled-editor handlers. Give the visible app a moment to hydrate.
    await new Promise((resolve) => setTimeout(resolve, 750));
    const input = findInput(kind);
    if (!input) throw new Error('No compatible signed-in message field is visible on this provider page.');
    const lastAssistant = lastAssistantDescriptor(kind);
    const submittedAt = Date.now();
    await setInput(input, task.prompt, kind);
    if (!inputMatches(input, task.prompt)) {
      const editor = `${input.tagName.toLowerCase()}${input.id ? `#${input.id}` : ''}`;
      throw new Error(
        `The complete prompt could not be inserted into the provider message field `
        + `(provider=${kind}, editor=${editor}, expected=${normalizedInputText(task.prompt).length}, `
        + `observed=${normalizedInputText(inputText(input)).length}).`,
      );
    }
    await submit(kind, input, task.prompt);
    // Some provider test/builds append the assistant node synchronously inside
    // the send click before MutationObserver delivery. Mark only elements beyond
    // the captured last-assistant boundary as post-submission candidates.
    for (const element of responseElements(kind)) {
      const descriptor = assistantDescriptor(element);
      if (descriptor.id === lastAssistant?.id || descriptor.fingerprint === lastAssistant?.fingerprint) continue;
      if (!elementFirstSeen.has(element)) elementFirstSeen.set(element, Date.now());
    }
    const record = {
      provider: kind,
      status: 'submitted',
      submittedAt,
      lastAssistantId: lastAssistant?.id || null,
      lastAssistantFingerprint: lastAssistant?.fingerprint || null,
      responseIdentity: null,
      recovered: false,
      sample: { previous: '', identity: null, stable: 0 },
    };
    taskRecords.set(taskId, record);
    persistTaskMetadata(taskId, record);
    return { success: true, submitted: true, task_id: taskId };
  } catch (error) {
    return { success: false, detail: error instanceof Error ? error.message : 'Browser invocation failed.' };
  }
}

function handleObserve(taskId) {
  const record = taskRecords.get(taskId) || recoverTaskMetadata(taskId);
  if (!record) return { state: 'failed', detail: 'Unknown or already-finalized task_id.' };
  if (record.status === 'cancelled') return { state: 'cancelled' };

  const kind = record.provider;
  const streaming = isStreaming(kind);
  const descriptor = correlatedAssistant(kind, record);
  const candidate = descriptor ? (descriptor.element.innerText || descriptor.element.textContent || '').trim() : '';
  const identity = descriptor?.id || descriptor?.fingerprint || null;

  if (identity && !record.responseIdentity) {
    record.responseIdentity = identity;
    persistTaskMetadata(taskId, record);
  }

  if (streaming) {
    if (candidate && (candidate !== record.sample.previous || identity !== record.sample.identity)) {
      record.sample.previous = candidate;
      record.sample.identity = identity;
      record.sample.stable = 0;
    }
    record.status = 'streaming';
    return { state: 'streaming' };
  }

  if (candidate.length >= 12) {
    if (candidate === record.sample.previous) record.sample.stable += 1;
    else { record.sample.previous = candidate; record.sample.stable = 0; }
    record.sample.identity = identity;
    if (record.sample.stable >= 1) {
      record.status = 'completed';
      persistTaskMetadata(taskId, record);
      return { state: 'completed', response: candidate };
    }
  }

  record.status = 'streaming';
  return { state: 'streaming' };
}

function handleCancel(taskId) {
  // Replace with a minimal tombstone: keeps the cancellation visible to a pending
  // observe call while discarding the baseline/sample state (the volatile record).
  taskRecords.set(taskId, { status: 'cancelled' });
  try {
    sessionStorage.setItem(sessionTaskKey(taskId), JSON.stringify({
      provider: provider(), status: 'cancelled', submittedAt: Date.now(),
      lastAssistantId: null, lastAssistantFingerprint: null, responseIdentity: null,
    }));
  } catch {}
  return { success: true, task_id: taskId };
}

async function composeExecute(task) {
  const taskId = typeof task?.task_id === 'string' && task.task_id
    ? task.task_id
    : `compat-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const submitResult = await handleSubmit({ ...task, task_id: taskId });
  if (!submitResult.success) throw new Error(submitResult.detail || 'Browser invocation failed.');

  const deadline = Date.now() + 180000;
  await new Promise((resolve) => setTimeout(resolve, 2000));
  while (Date.now() < deadline) {
    const observation = handleObserve(taskId);
    if (observation.state === 'completed') return observation.response;
    if (observation.state === 'cancelled') throw new Error('The task was cancelled.');
    if (observation.state === 'failed' && !taskRecords.has(taskId)) throw new Error(observation.detail || 'Browser invocation failed.');
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error('The visible provider response did not complete before the Enkstein timeout.');
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'marcellus-status') {
    sendResponse({ ready: Boolean(findInput(provider())) });
    return false;
  }
  if (message?.type === 'marcellus-submit') {
    handleSubmit(message.task).then(sendResponse);
    return true;
  }
  if (message?.type === 'marcellus-observe') {
    sendResponse(handleObserve(message.task_id));
    return false;
  }
  if (message?.type === 'marcellus-cancel') {
    sendResponse(handleCancel(message.task_id));
    return false;
  }
  if (message?.type === 'marcellus-execute') {
    composeExecute(message.task).then((response) => sendResponse({ success: true, response })).catch((error) => {
      sendResponse({ success: false, detail: error instanceof Error ? error.message : 'Browser invocation failed.' });
    });
    return true;
  }
  return false;
});

setInterval(() => chrome.runtime.sendMessage({ type: 'marcellus-heartbeat' }), 2000);
chrome.runtime.sendMessage({ type: 'marcellus-heartbeat' });
