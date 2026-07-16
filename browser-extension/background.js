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
const tabsUpdate = (tabId, update) => new Promise((resolve) => chrome.tabs.update(tabId, update, resolve));
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

function safeProviderUrl(url, expectedProvider) {
  try {
    const parsed = new URL(url);
    const sanitized = `${parsed.origin}${parsed.pathname}`;
    return providerForUrl(`${sanitized}/`) === expectedProvider ? sanitized : null;
  } catch {
    return null;
  }
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

async function waitForProviderReady(tabId, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const status = await sendToTab(tabId, { type: 'marcellus-status' });
      if (status?.ready) return true;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error('Provider page did not expose a compatible signed-in message field');
}

async function sessionTab(task) {
  const sessionKey = task.session_id ? `${task.provider}:${task.session_id}` : null;
  const stored = await storageGet('marcellusSessionTabs');
  const mappings = stored.marcellusSessionTabs || {};
  if (sessionKey && mappings[sessionKey]) {
    const mapping = typeof mappings[sessionKey] === 'number'
      ? { tab_id: mappings[sessionKey] }
      : mappings[sessionKey];
    try {
      const existing = await tabsGet(mapping.tab_id);
      if (existing?.id && providerForUrl(existing.url) === task.provider) {
        await tabsUpdate(existing.id, { active: true });
        await waitForTab(existing.id);
        await waitForProviderReady(existing.id);
        return existing;
      }
    } catch {}
    const restoredUrl = safeProviderUrl(mapping.url, task.provider);
    if (restoredUrl) {
      const restored = await tabsCreate({ url: restoredUrl, active: true });
      await waitForTab(restored.id);
      await waitForProviderReady(restored.id);
      mappings[sessionKey] = { tab_id: restored.id, url: restoredUrl };
      await storageSet({ marcellusSessionTabs: mappings });
      return restored;
    }
  }

  const created = await tabsCreate({ url: providerUrl(task.provider), active: true });
  await waitForTab(created.id);
  await waitForProviderReady(created.id);
  if (sessionKey) {
    mappings[sessionKey] = {
      tab_id: created.id,
      url: safeProviderUrl(created.url, task.provider) || providerUrl(task.provider),
    };
    await storageSet({ marcellusSessionTabs: mappings });
  }
  return created;
}

async function rememberSessionTab(task, tabId) {
  if (!task.session_id) return;
  const tab = await tabsGet(tabId);
  const url = safeProviderUrl(tab?.url, task.provider);
  if (!url) return;
  const sessionKey = `${task.provider}:${task.session_id}`;
  const stored = await storageGet('marcellusSessionTabs');
  const mappings = stored.marcellusSessionTabs || {};
  mappings[sessionKey] = { tab_id: tabId, url };
  await storageSet({ marcellusSessionTabs: mappings });
}

async function executeTask(task) {
  const tab = await sessionTab(task);
  await tabsUpdate(tab.id, { active: true });
  try {
    const result = await sendToTab(tab.id, { type: 'marcellus-execute', task });
    await rememberSessionTab(task, tab.id);
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
chrome.tabs.onRemoved.addListener(async (tabId) => {
  const stored = await storageGet('marcellusSessionTabs');
  const mappings = stored.marcellusSessionTabs || {};
  let changed = false;
  for (const [key, value] of Object.entries(mappings)) {
    const mapping = typeof value === 'number' ? { tab_id: value } : value;
    if (mapping?.tab_id === tabId) {
      const provider = key.split(':', 1)[0];
      const url = safeProviderUrl(mapping.url, provider);
      if (url) mappings[key] = { tab_id: null, url };
      else delete mappings[key];
      changed = true;
    }
  }
  if (changed) await storageSet({ marcellusSessionTabs: mappings });
});
setInterval(poll, 1500);
void poll();
