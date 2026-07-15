const BRIDGE = 'http://127.0.0.1:47831';
let polling = false;

const storageGet = (key) => new Promise((resolve) => chrome.storage.local.get(key, resolve));
const storageSet = (value) => new Promise((resolve) => chrome.storage.local.set(value, resolve));
const tabsQuery = (query) => new Promise((resolve) => chrome.tabs.query(query, resolve));
const tabsGet = (tabId) => new Promise((resolve, reject) => chrome.tabs.get(tabId, (tab) => {
  if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
  else resolve(tab);
}));
const tabsCreate = (create) => new Promise((resolve) => chrome.tabs.create(create, resolve));
const sendToTab = (tabId, message) => new Promise((resolve, reject) => {
  chrome.tabs.sendMessage(tabId, message, (response) => {
    if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
    else resolve(response);
  });
});

function providerForUrl(url = '') {
  if (url.startsWith('https://chatgpt.com/')) return 'chatgpt';
  if (url.startsWith('https://claude.ai/')) return 'claude';
  if (url.startsWith('https://gemini.google.com/')) return 'gemini';
  return null;
}

function providerUrl(provider) {
  if (provider === 'chatgpt') return 'https://chatgpt.com/';
  if (provider === 'claude') return 'https://claude.ai/new';
  return 'https://gemini.google.com/app';
}

async function bridgeRequest(path, { token, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['X-Marcellus-Browser-Token'] = token;
  const response = await fetch(`${BRIDGE}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body || {}),
  });
  if (!response.ok) throw new Error(`Bridge rejected request (${response.status})`);
  return response.json();
}

async function pair(code) {
  const result = await bridgeRequest('/v1/browser/exchange', { body: { code } });
  if (!result.token) throw new Error('Pairing returned no local token');
  await storageSet({ marcellusBrowserToken: result.token });
  return true;
}

async function availableProviders() {
  const tabs = await tabsQuery({ url: [
    'https://chatgpt.com/*',
    'https://claude.ai/*',
    'https://gemini.google.com/*',
  ] });
  const ready = [];
  for (const tab of tabs) {
    const provider = providerForUrl(tab.url);
    if (!provider || !tab.id) continue;
    try {
      const status = await sendToTab(tab.id, { type: 'marcellus-status' });
      if (status?.ready) ready.push(provider);
    } catch {}
  }
  return [...new Set(ready)];
}

async function waitForTab(tabId, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const tab = await tabsGet(tabId);
    if (tab?.status === 'complete') return tab;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error('Provider page did not finish loading');
}

async function executeTask(task) {
  const tab = await tabsCreate({ url: providerUrl(task.provider), active: true });
  await waitForTab(tab.id);
  chrome.tabs.update(tab.id, { active: true });
  try {
    const result = await sendToTab(tab.id, { type: 'marcellus-execute', task });
    return result || { success: false, detail: 'Provider page returned no result.' };
  } catch (error) {
    return { success: false, detail: error instanceof Error ? error.message : 'Provider page invocation failed.' };
  }
}

async function poll() {
  if (polling) return;
  polling = true;
  try {
    const stored = await storageGet('marcellusBrowserToken');
    const token = stored.marcellusBrowserToken;
    if (!token) return;
    const providers = await availableProviders();
    const result = await bridgeRequest('/v1/browser/poll', { token, body: { providers } });
    if (!result.task) return;
    const completion = await executeTask(result.task);
    await bridgeRequest('/v1/browser/complete', {
      token,
      body: {
        task_id: result.task.task_id,
        success: Boolean(completion.success),
        response: completion.response || '',
        detail: completion.detail || '',
      },
    });
  } catch (error) {
    if (String(error).includes('(401)')) await chrome.storage.local.remove('marcellusBrowserToken');
  } finally {
    polling = false;
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'marcellus-pair') {
    pair(message.code).then(() => sendResponse({ success: true })).catch((error) => {
      sendResponse({ success: false, detail: error instanceof Error ? error.message : 'Pairing failed.' });
    });
    return true;
  }
  if (message?.type === 'marcellus-heartbeat') {
    void poll();
    sendResponse({ success: true });
    return false;
  }
  return false;
});

chrome.runtime.onInstalled.addListener(() => chrome.alarms.create('marcellus-poll', { periodInMinutes: 0.5 }));
chrome.alarms.onAlarm.addListener((alarm) => { if (alarm.name === 'marcellus-poll') void poll(); });
setInterval(poll, 1500);
void poll();
