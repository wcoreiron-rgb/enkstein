const BRIDGE = 'http://127.0.0.1:47831';
let polling = false;

const LEASE_MS = 20000;
const MAX_ATTEMPTS = 2;
const TERMINAL_STATES = ['completed', 'failed', 'cancelled', 'expired'];
const JOURNAL_ALLOWLIST = [
  'task_id', 'provider', 'session_id', 'state',
  'leased_at', 'lease_expires_at', 'attempts',
  'tab_id', 'url', 'progress_at', 'error_code',
];
const ERROR_CODES = new Set([
  'provider_not_ready', 'submit_failed', 'observation_failed',
  'bridge_unavailable', 'expired', 'cancelled', 'retry_exhausted',
]);

// Volatile, in-memory only: the prompt payload for a leased task. Never persisted to storage.
// Lost on service-worker restart by design; a restart forces a native re-lease to recover it.
const volatileTasks = new Map();
// Detailed operator errors are transient only. chrome.storage receives only a
// bounded error_code enum, never provider page text, paths, prompts or tokens.
const transientErrors = new Map();
let capabilitiesCache = { checked_at: 0, ok: false };

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

function sanitizeJournalEntry(entry) {
  const clean = {};
  for (const key of JOURNAL_ALLOWLIST) {
    if (key in entry && entry[key] !== undefined) clean[key] = entry[key];
  }
  if (clean.error_code && !ERROR_CODES.has(clean.error_code)) delete clean.error_code;
  return clean;
}

function sanitizeJournal(journal) {
  const clean = {};
  for (const [taskId, entry] of Object.entries(journal || {})) {
    clean[taskId] = sanitizeJournalEntry(entry);
  }
  return clean;
}

async function loadJournal() {
  const stored = await storageGet('marcellusTaskJournal');
  return stored.marcellusTaskJournal || {};
}

async function saveJournal(journal) {
  await storageSet({ marcellusTaskJournal: sanitizeJournal(journal) });
}

async function upsertJournalEntry(entry) {
  const journal = await loadJournal();
  journal[entry.task_id] = sanitizeJournalEntry(entry);
  await saveJournal(journal);
  return journal[entry.task_id];
}

async function removeJournalEntry(taskId) {
  const journal = await loadJournal();
  delete journal[taskId];
  await saveJournal(journal);
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

async function getCapabilities(token) {
  const now = Date.now();
  if (now - capabilitiesCache.checked_at < 30000) return capabilitiesCache.ok;
  let ok = false;
  try {
    await bridgeRequest('/v1/browser/capabilities', { token });
    ok = true;
  } catch {
    ok = false;
  }
  capabilitiesCache = { checked_at: now, ok };
  return ok;
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

async function refreshSessionMappingsForTab(tabId, candidateUrl) {
  const stored = await storageGet('marcellusSessionTabs');
  const mappings = stored.marcellusSessionTabs || {};
  let changed = false;
  for (const [key, value] of Object.entries(mappings)) {
    const mapping = typeof value === 'number' ? { tab_id: value } : value;
    if (mapping?.tab_id !== tabId) continue;
    const provider = key.split(':', 1)[0];
    const url = safeProviderUrl(candidateUrl, provider);
    if (url && url !== mapping.url) {
      mappings[key] = { tab_id: tabId, url };
      changed = true;
    }
  }
  if (changed) await storageSet({ marcellusSessionTabs: mappings });
}

function transientError(taskId, fallback) {
  return transientErrors.get(taskId) || fallback;
}

async function expireEntry(entry, token) {
  entry.state = 'expired';
  entry.error_code = 'expired';
  entry.progress_at = Date.now();
  await upsertJournalEntry(entry);
  volatileTasks.delete(entry.task_id);
  transientErrors.set(entry.task_id, 'Task lease expired.');
  try {
    await bridgeRequest('/v1/browser/complete', { token, body: { task_id: entry.task_id, success: false, response: '', detail: transientError(entry.task_id, 'Task lease expired.') } });
  } catch {}
  transientErrors.delete(entry.task_id);
  await removeJournalEntry(entry.task_id);
}

async function failEntry(entry, token, errorCode, detail) {
  entry.state = 'failed';
  entry.error_code = ERROR_CODES.has(errorCode) ? errorCode : 'observation_failed';
  entry.progress_at = Date.now();
  transientErrors.set(entry.task_id, detail || 'The provider task failed.');
  await upsertJournalEntry(entry);
  volatileTasks.delete(entry.task_id);
  try {
    await bridgeRequest('/v1/browser/complete', { token, body: { task_id: entry.task_id, success: false, response: '', detail: transientError(entry.task_id, 'The provider task failed.') } });
  } catch {}
  transientErrors.delete(entry.task_id);
  await removeJournalEntry(entry.task_id);
}

async function cancelEntry(entry, token) {
  entry.state = 'cancelled';
  entry.error_code = 'cancelled';
  entry.progress_at = Date.now();
  await upsertJournalEntry(entry);
  volatileTasks.delete(entry.task_id);
  if (entry.tab_id) {
    try { await sendToTab(entry.tab_id, { type: 'marcellus-cancel', task_id: entry.task_id }); } catch {}
  }
  try {
    await bridgeRequest('/v1/browser/complete', { token, body: { task_id: entry.task_id, success: false, response: '', detail: 'Task cancelled.' } });
  } catch {}
  await removeJournalEntry(entry.task_id);
}

async function advanceEntry(entry, token) {
  const now = Date.now();
  try {
    if (entry.state === 'leased') {
      let volatile = volatileTasks.get(entry.task_id);
      if (!volatile) {
        // Service worker restarted after the native side leased this task but before it was
        // submitted. The prompt was never journaled, so recover it via a native re-lease.
        const result = await bridgeRequest('/v1/browser/poll', {
          token,
          body: { providers: await availableProviders(), task_id: entry.task_id },
        }).catch(() => null);
        if (!result?.task || result.task.task_id !== entry.task_id) {
          if (entry.lease_expires_at < now) await expireEntry(entry, token);
          return;
        }
        volatile = result.task;
        volatileTasks.set(entry.task_id, volatile);
      }

      if (entry.lease_expires_at < now) {
        if (entry.attempts >= MAX_ATTEMPTS) {
          await expireEntry(entry, token);
          return;
        }
        entry.attempts += 1;
        entry.lease_expires_at = now + LEASE_MS;
        await upsertJournalEntry(entry);
      }

      const tab = await sessionTab(volatile);
      await tabsUpdate(tab.id, { active: true });
      entry.tab_id = tab.id;
      entry.url = safeProviderUrl(tab.url, entry.provider);
      await upsertJournalEntry(entry);

      const submitResult = await sendToTab(tab.id, { type: 'marcellus-submit', task: volatile }).catch((error) => (
        { success: false, detail: error instanceof Error ? error.message : 'Submission failed.' }
      ));

      if (!submitResult?.success) {
        entry.attempts += 1;
        entry.error_code = submitResult?.detail?.includes('message field')
          ? 'provider_not_ready'
          : 'submit_failed';
        transientErrors.set(entry.task_id, submitResult?.detail || 'Submission failed.');
        entry.progress_at = now;
        if (entry.attempts >= MAX_ATTEMPTS) {
          await failEntry(entry, token, 'retry_exhausted', transientError(entry.task_id, 'Submission retry exhausted.'));
          return;
        }
        await upsertJournalEntry(entry);
        return;
      }

      entry.state = 'submitted';
      entry.progress_at = now;
      delete entry.error_code;
      transientErrors.delete(entry.task_id);
      await upsertJournalEntry(entry);
      await bridgeRequest('/v1/browser/ack', { token, body: { task_id: entry.task_id } }).catch(() => {});
      await rememberSessionTab(volatile, tab.id);
      return;
    }

    if (entry.state === 'submitted' || entry.state === 'streaming') {
      if (!entry.tab_id) return;
      try {
        const currentTab = await tabsGet(entry.tab_id);
        await refreshSessionMappingsForTab(entry.tab_id, currentTab?.url);
        if (entry.session_id) await rememberSessionTab(entry, entry.tab_id);
      } catch {}
      const observation = await sendToTab(entry.tab_id, { type: 'marcellus-observe', task_id: entry.task_id }).catch((error) => (
        { state: 'failed', detail: error instanceof Error ? error.message : 'Observation failed.' }
      ));

      if (observation?.state === 'streaming') {
        entry.state = 'streaming';
        entry.progress_at = now;
        await upsertJournalEntry(entry);
        await bridgeRequest('/v1/browser/progress', {
          token,
          body: { task_id: entry.task_id, state: 'streaming', detail: '' },
        }).catch(() => {});
        return;
      }

      if (observation?.state === 'completed') {
        await bridgeRequest('/v1/browser/complete', {
          token,
          body: {
            task_id: entry.task_id,
            success: true,
            response: observation.response || '',
            detail: '',
            // Files the provider actually generated for this turn. Empty
            // whenever the answer produced no downloads.
            attachments: Array.isArray(observation.attachments) ? observation.attachments : [],
          },
        }).catch(() => {});
        entry.state = 'completed';
        entry.progress_at = now;
        await upsertJournalEntry(entry);
        volatileTasks.delete(entry.task_id);
        transientErrors.delete(entry.task_id);
        await removeJournalEntry(entry.task_id);
        return;
      }

      if (observation?.state === 'cancelled') {
        await cancelEntry(entry, token);
        return;
      }

      await failEntry(entry, token, 'observation_failed', observation?.detail);
    }
  } catch (error) {
    entry.error_code = 'bridge_unavailable';
    transientErrors.set(entry.task_id, error instanceof Error ? error.message : 'Journal advance failed.');
    entry.progress_at = Date.now();
    await upsertJournalEntry(entry);
  }
}

async function processJournal(token) {
  const journal = await loadJournal();
  for (const entry of Object.values(journal)) {
    if (TERMINAL_STATES.includes(entry.state)) continue;
    await advanceEntry(entry, token);
  }
}

async function legacyProcessTask(task, token) {
  let entry = sanitizeJournalEntry({
    task_id: task.task_id,
    provider: task.provider,
    session_id: task.session_id || null,
    state: 'leased',
    leased_at: Date.now(),
    lease_expires_at: Date.now() + LEASE_MS,
    attempts: 1,
    tab_id: null,
    url: null,
    progress_at: Date.now(),
    error_code: 'bridge_unavailable',
  });
  entry = await upsertJournalEntry(entry);

  let completion;
  try {
    const tab = await sessionTab(task);
    entry.tab_id = tab.id;
    entry.url = safeProviderUrl(tab.url, task.provider);
    entry.state = 'submitted';
    await upsertJournalEntry(entry);
    await tabsUpdate(tab.id, { active: true });
    completion = await sendToTab(tab.id, { type: 'marcellus-execute', task });
    await rememberSessionTab(task, tab.id);
  } catch (error) {
    completion = { success: false, detail: error instanceof Error ? error.message : 'Provider page invocation failed.' };
  }

  entry.state = completion.success ? 'completed' : 'failed';
  if (completion.success) delete entry.error_code;
  else entry.error_code = 'bridge_unavailable';
  entry.progress_at = Date.now();
  await upsertJournalEntry(entry);
  await bridgeRequest('/v1/browser/complete', {
    token,
    body: {
      task_id: task.task_id,
      success: Boolean(completion.success),
      response: completion.response || '',
      detail: completion.detail || '',
    },
  }).catch(() => {});
  await removeJournalEntry(task.task_id);
}

async function handleBridgeCancelSignal(result, token) {
  if (!result?.cancel_task_id) return;
  const journal = await loadJournal();
  const entry = journal[result.cancel_task_id];
  if (entry && !TERMINAL_STATES.includes(entry.state)) await cancelEntry(entry, token);
}

async function poll() {
  if (polling) return;
  polling = true;
  try {
    const stored = await storageGet('marcellusBrowserToken');
    const token = stored.marcellusBrowserToken;
    if (!token) return;

    const capabilitiesOk = await getCapabilities(token);

    if (capabilitiesOk) {
      await processJournal(token);
      const journal = await loadJournal();
      const hasActive = Object.values(journal).some((entry) => !TERMINAL_STATES.includes(entry.state));
      const providers = await availableProviders();
      if (hasActive) {
        // Still check in while a turn is in flight. Readiness would otherwise
        // depend entirely on progress events, and a provider that streams
        // nothing observable for a while (a long ChatGPT "thinking" pause)
        // would let the bridge mark a perfectly healthy session stale.
        // The keepalive flag stops the bridge from leasing a second task or
        // rewinding this one's state, so it refreshes readiness and nothing else.
        const keepalive = await bridgeRequest('/v1/browser/poll', {
          token,
          body: { providers, keepalive: true },
        }).catch(() => null);
        await handleBridgeCancelSignal(keepalive, token);
      } else {
        const result = await bridgeRequest('/v1/browser/poll', { token, body: { providers } }).catch(() => null);
        await handleBridgeCancelSignal(result, token);
        if (result?.task?.task_id) {
          volatileTasks.set(result.task.task_id, result.task);
          const entry = {
            task_id: result.task.task_id,
            provider: result.task.provider,
            session_id: result.task.session_id || null,
            state: 'leased',
            leased_at: Date.now(),
            lease_expires_at: Date.now() + LEASE_MS,
            attempts: 1,
            tab_id: null,
            url: null,
            progress_at: Date.now(),
          };
          await upsertJournalEntry(entry);
          await advanceEntry(entry, token);
        }
      }
    } else {
      const providers = await availableProviders();
      const result = await bridgeRequest('/v1/browser/poll', { token, body: { providers } }).catch(() => null);
      await handleBridgeCancelSignal(result, token);
      if (result?.task?.task_id) await legacyProcessTask(result.task, token);
    }
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

// chrome.alarms.create is idempotent (re-creating with the same name just
// resets its schedule), so this runs on every event that can wake the
// service worker -- not only onInstalled, which does not fire on ordinary
// worker restarts/suspend-resume cycles -- to make sure the alarm always
// exists even if it was somehow lost.
function ensurePollAlarm() { chrome.alarms.create('marcellus-poll', { periodInMinutes: 0.5 }); }
chrome.runtime.onInstalled.addListener(ensurePollAlarm);
chrome.runtime.onStartup?.addListener(ensurePollAlarm);
ensurePollAlarm();
chrome.alarms.onAlarm.addListener((alarm) => { if (alarm.name === 'marcellus-poll') void poll(); });
// Switching back to (or opening) a signed-in provider tab should reflect as
// connected immediately rather than waiting for the next alarm tick, since
// chrome.alarms has a 30-second floor and this is the moment the user is
// most likely to actually use the Brain.
chrome.tabs.onActivated?.addListener(() => void poll());
chrome.windows?.onFocusChanged?.addListener((windowId) => {
  if (windowId !== chrome.windows.WINDOW_ID_NONE) void poll();
});
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
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const candidateUrl = changeInfo?.url || tab?.url;
  if (candidateUrl) void refreshSessionMappingsForTab(tabId, candidateUrl);
  if (changeInfo?.status === 'complete' && candidateUrl && providerForUrl(candidateUrl)) void poll();
});
// Runs on every service-worker load, including restarts: resumes any nonterminal journal entries.
void poll();
setInterval(poll, 1500);
